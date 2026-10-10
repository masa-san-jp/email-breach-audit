"""Email breach investigation tool; behavior is defined by SPEC.md v0.14."""
import argparse
import calendar
import collections
import csv
import datetime as dt
import html
import http.client
import io
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request

__version__ = '0.1.0'
SCHEMA_VERSION = 2
PROVIDERS = ('hibp', 'leakcheck', 'hudsonrock', 'xon')
FLAGS = ('stealer_log', 'spam_list', 'fabricated', 'unverified', 'malware')
def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f'{seconds:.1f} 秒'
    return f'約 {math.ceil(seconds / 60)} 分'


RISKS = dict(critical='緊急', high='高', medium='中', low='低', none='検出なし', unknown='判定不能')
NAMES = dict(hibp='Have I Been Pwned', leakcheck='LeakCheck Public API',
             hudsonrock='Hudson Rock Cavalier OSINT', xon='XposedOrNot')
CONFIRMATION = dict(hibp='文書（カタログは実測）', leakcheck='実測',
                    hudsonrock='応答は実測。規約とレート制限は未確認', xon='実測')
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CATALOGS = dict(hibp='https://haveibeenpwned.com/api/v3/breaches',
                xon='https://api.xposedornot.com/v1/breaches')
SUMMARY = ('email risk risk_label coverage breaches password_breaches recent_password_breaches '
           'undated_password_breaches stealer_log_breaches latest_breach infostealer_infections '
           'infostealer_latest providers_ok providers_error providers_not_queried providers_skipped breach_names').split()
FINDINGS = ('email risk breach breach_date breach_date_precision added_date effective_date recent '
            'in_scope has_password flags catalog_miss providers data_classes').split()
COLUMNS = ['provider', 'email', 'status', 'data', 'fetched_at', 'schema_version']
TABLE_SQL = ('CREATE TABLE results(provider TEXT, email TEXT, status TEXT, data TEXT, '
             'fetched_at TEXT, schema_version INTEGER, PRIMARY KEY(provider,email))')


def http_get(url: str, headers: dict[str, str], timeout: float) -> tuple[int, dict[str, str], bytes]:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        # Redirect targets are not among the allowed §5 endpoints.
        def redirect_request(self, req, fp, code, msg, response_headers, newurl):
            return None

    request = urllib.request.Request(url, headers=headers, method='GET')
    try:
        response = urllib.request.build_opener(NoRedirect()).open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (OSError, http.client.HTTPException)):
            raise exc.reason
        raise OSError('network request failed') from exc
    with response:
        return response.code, {k.lower(): v for k, v in response.headers.items()}, response.read()


def sleep(seconds: float, stop: threading.Event) -> bool:
    return stop.wait(seconds)


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def today_local() -> dt.date:
    return dt.date.today()


def log(message):
    print(message, file=sys.stderr, flush=True)


def positive_int(text):
    try:
        value = int(text)
        if value >= 1:
            return value
    except ValueError:
        pass
    raise argparse.ArgumentTypeError('1 以上の整数を指定してください')


def parse_args(argv):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('input')
    parser.add_argument('-o', '--outdir', default='~/breach-check-output')
    parser.add_argument('--providers', default='hibp,leakcheck')
    parser.add_argument('--max-age', type=positive_int, default=7)
    parser.add_argument('--recent-years', type=positive_int, default=3)
    parser.add_argument('--limit', type=positive_int)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--refresh', action='store_true')
    group.add_argument('--report-only', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--version', action='version', version=f'email-breach-audit {__version__}')
    args = parser.parse_args(argv)
    if args.max_age > 36500:
        parser.error('--max-age は 36500 以下にしてください')
    if args.recent_years > 100:
        parser.error('--recent-years は 100 以下にしてください')
    ids = {p.strip().lower() for p in args.providers.split(',') if p.strip()}
    if not ids:
        parser.error('プロバイダが指定されていません')
    if ids - set(PROVIDERS):
        parser.error('不明なプロバイダ')
    args.providers = [p for p in PROVIDERS if p in ids]
    return args


def read_input(args):
    with open(args.input, encoding='utf-8-sig') as stream:
        lines = list(stream)
    count = extracted = missing = 0
    emails = []
    seen = set()
    for line in lines:
        if line.strip().startswith('#'):
            continue
        count += 1
        matches = EMAIL_RE.findall(line)
        extracted += len(matches)
        missing += bool(line.strip()) and not matches
        for email in matches:
            email = email.lower()
            if email not in seen:
                seen.add(email)
                emails.append(email)
    chosen = emails[:args.limit] if args.limit else emails
    log(f'入力: 行 {count} / 抽出 {extracted} / 重複除外後 {len(emails)} / アドレスなし {missing} / 処理 {len(chosen)}')
    return chosen


def date_value(value, mode='day'):
    if not isinstance(value, str):
        return '', 'unknown'
    if mode == 'iso':
        value = value[:10]
    pattern = r'[0-9]{4}-[0-9]{2}-[0-9]{2}'
    precision = 'day'
    if mode == 'flex' and re.fullmatch(r'[0-9]{4}(-[0-9]{2})?', value):
        precision = 'month' if len(value) == 7 else 'year'
    elif not re.fullmatch(pattern, value):
        return '', 'unknown'
    try:
        compare_date(value, precision)
    except (ValueError, OverflowError):
        return '', 'unknown'
    return value, precision


def compare_date(value, precision):
    if precision == 'unknown' or not value:
        return None
    if precision == 'year':
        return dt.date(int(value), 12, 31)
    if precision == 'month':
        year, month = map(int, value.split('-'))
        return dt.date(year, month, calendar.monthrange(year, month)[1])
    return dt.date.fromisoformat(value)


def new_source(name, date='', precision='unknown', added='', data=None, password=None, flags=None, miss=False):
    return dict(name=name, breach_date=date, breach_date_precision=precision,
                added_date=added, data=data or [], has_password=password,
                flags=flags or [], catalog_miss=miss)


def string_array(value):
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def classify(provider, status, body, catalog=False):
    """Return (classification, reason, decoded payload)."""
    if not catalog and provider in ('hibp', 'xon') and status == 404:
        return 'ok', '', [] if provider == 'hibp' else {'Error': 'Not found'}
    if status != 200:
        kind = 'invalid' if status in (400, 422) else 'fatal' if status in (401, 403) else 'rate' if status == 429 else 'transient'
        return kind, f'HTTP {status}', None
    try:
        obj = json.loads(body)
    except (ValueError, UnicodeError):
        return 'transient', 'bad response', None
    if catalog:
        valid = isinstance(obj, list) if provider == 'hibp' else isinstance(obj, dict) and isinstance(obj.get('exposedBreaches'), list)
    elif provider == 'hibp':
        valid = isinstance(obj, list) and bool(obj) and all(isinstance(s, dict) and isinstance(s.get('Name'), str) for s in obj)
    elif provider == 'leakcheck':
        valid = isinstance(obj, dict) and type(obj.get('success')) is bool
        if valid and obj['success'] is False:
            error = obj.get('error')
            if isinstance(error, str) and error.strip() == 'Not found':
                return 'ok', '', {'success': True, 'sources': []}
            reason = 'leakcheck: ' + (EMAIL_RE.sub('<email>', error.strip())[:100] if isinstance(error, str) else 'no error message')
            rate = isinstance(error, str) and ('limit' in error.lower() or 'too many' in error.lower())
            return ('rate' if rate else 'invalid'), reason, None
        if valid:
            valid = (isinstance(obj.get('sources'), list) and
                     all(isinstance(s, dict) and isinstance(s.get('name'), str) for s in obj['sources']) and
                     string_array(obj.get('fields', [])))
    elif provider == 'hudsonrock':
        valid = isinstance(obj, dict) and isinstance(obj.get('stealers'), list) and all(isinstance(s, dict) for s in obj['stealers'])
    else:
        valid = isinstance(obj, dict) and (obj.get('Error') == 'Not found' or
                isinstance(obj.get('breaches'), list) and all(string_array(s) for s in obj['breaches']))
    return ('ok', '', obj) if valid else ('transient', 'bad response', None)


def request_with_retry(provider, url, headers, stop, catalog=False):
    consecutive = 0
    for attempt in range(1, 9):
        try:
            status, response_headers, body = http_get(url, headers, 30)
            kind, reason, payload = classify(provider, status, body, catalog)
        except (OSError, http.client.HTTPException) as exc:
            kind, reason, payload = 'transient', f'network: {type(exc).__name__}', None
            response_headers = {}
        if kind in ('ok', 'invalid', 'fatal'):
            return kind, reason, payload
        if stop.is_set():
            return 'interrupted', reason, None
        if kind == 'rate':
            value = response_headers.get('retry-after', '').strip(' \t\n\r\v\f')
            retry = int(value) if re.fullmatch(r'[0-9]+', value) else None
            consecutive = consecutive + 1 if retry is None else 0
            if (retry is not None and retry > 600) or consecutive >= 3 or attempt == 8:
                return 'limit', reason, None
            delay = retry + 1 if retry is not None else 30 * attempt
        else:
            consecutive = 0
            if attempt == 8:
                return 'transient', reason, None
            delay = 5 * attempt
        if sleep(delay, stop):
            stop.set()
            return 'interrupted', reason, None
    raise AssertionError('unreachable')


def catalog_map(provider, payload):
    values = payload if provider == 'hibp' else payload['exposedBreaches']
    key = 'Name' if provider == 'hibp' else 'breachID'
    result = {}
    for item in values:
        if isinstance(item, dict) and isinstance(item.get(key), str):
            result.setdefault(item[key], item)
    return result


def normalize(provider, payload, catalog):
    extra = {}
    sources = []
    if provider == 'hudsonrock':
        stealers = payload['stealers']
        dates = [date_value(s.get('date_compromised'), 'iso')[0] for s in stealers]
        extra = dict(infections=len(stealers), compromised_dates=sorted(d for d in dates if d),
                     corporate_services=sum(s.get('total_corporate_services', 0) if type(s.get('total_corporate_services')) is int else 0 for s in stealers),
                     user_services=sum(s.get('total_user_services', 0) if type(s.get('total_user_services')) is int else 0 for s in stealers))
        found = bool(stealers)
    elif provider == 'leakcheck':
        fields = payload.get('fields', []) if payload['sources'] else []
        extra = dict(fields=fields, password_field='password' in fields)
        for item in payload['sources']:
            date, precision = date_value(item.get('date'), 'flex')
            sources.append(new_source(item['name'], date, precision))
        found = bool(sources)
    else:
        names = [s['Name'] for s in payload] if provider == 'hibp' else ([] if payload.get('Error') == 'Not found' else [name for group in payload['breaches'] for name in group])
        for name in names:
            item = catalog.get(name)
            if item is None:
                sources.append(new_source(name, miss=True))
                continue
            if provider == 'hibp':
                title = item.get('Title')
                display = title if isinstance(title, str) and title.strip() else name
                date, precision = date_value(item.get('BreachDate'))
                added = date_value(item.get('AddedDate'), 'iso')[0]
                data = item.get('DataClasses')
                flags = [flag for key, flag, expected in (
                    ('IsStealerLog', 'stealer_log', True), ('IsSpamList', 'spam_list', True),
                    ('IsFabricated', 'fabricated', True), ('IsVerified', 'unverified', False),
                    ('IsMalware', 'malware', True)) if item.get(key) is expected]
            else:
                display = name
                date, precision = date_value(item.get('breachedDate'), 'iso')
                added = date_value(item.get('addedDate'), 'iso')[0]
                data = item.get('exposedData')
                flags = ['unverified'] if item.get('verified') is False else []
            password = 'Passwords' in data if string_array(data) else None
            sources.append(new_source(display, date, precision, added,
                                      data if string_array(data) else [], password, flags))
        found = bool(sources)
    return dict(found=found, sources=sources, extra=extra)


def valid_cache_row(provider, status, data, fetched, version):
    """Validate row contents independently of the SQLite schema (§7.1)."""
    if type(version) is not int or status not in ('ok', 'error'):
        return False
    if not isinstance(fetched, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', fetched):
        return False
    dt.datetime.fromisoformat(fetched.replace('Z', '+00:00'))
    if not isinstance(data, dict):
        return False
    if status == 'error':
        return data.get('kind') in ('transient', 'invalid') and isinstance(data.get('reason'), str)
    if type(data.get('found')) is not bool or not isinstance(data.get('sources'), list) or not isinstance(data.get('extra'), dict):
        return False
    for item in data['sources']:
        if not isinstance(item, dict) or not isinstance(item.get('name'), str):
            return False
        precision = item.get('breach_date_precision')
        date = item.get('breach_date')
        mode = 'flex' if precision in ('month', 'year') else 'day'
        if not isinstance(date, str) or precision not in ('day', 'month', 'year', 'unknown') or date_value(date, mode) != (date, precision):
            return False
        added = item.get('added_date')
        if not isinstance(added, str) or date_value(added)[0] != added:
            return False
        if not string_array(item.get('data')) or not (item.get('has_password') is None or type(item.get('has_password')) is bool) or 'has_password' not in item:
            return False
        flags = item.get('flags')
        if not string_array(flags) or flags != [flag for flag in FLAGS if flag in flags] or type(item.get('catalog_miss')) is not bool:
            return False
    extra = data['extra']
    if provider == 'leakcheck':
        return string_array(extra.get('fields')) and type(extra.get('password_field')) is bool
    if provider == 'hudsonrock':
        dates = extra.get('compromised_dates')
        return (all(type(extra.get(k)) is int for k in ('infections', 'corporate_services', 'user_services')) and
                string_array(dates) and dates == sorted(dates) and
                all(date_value(d)[0] == d and bool(d) for d in dates))
    return extra == {}


class Cache:
    def __init__(self, path, readonly=False):
        self.lock = threading.Lock()
        self.db = None
        self.rows = {}
        if readonly and not path.exists():
            return
        try:
            self.db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, check_same_thread=False) if readonly else sqlite3.connect(path, check_same_thread=False)
            if not readonly:
                self.db.execute('PRAGMA journal_mode=DELETE')
            info = list(self.db.execute('PRAGMA table_info(results)'))
            if not info:
                if readonly:
                    return
                self.db.execute(TABLE_SQL)
                self.db.commit()
            elif ([c[1] for c in info] != COLUMNS or [c[5] for c in info] != [1, 2, 0, 0, 0, 0]):
                raise sqlite3.DatabaseError('cache schema mismatch')
            for provider, email, status, data, fetched, version in self.db.execute('SELECT * FROM results'):
                try:
                    decoded = json.loads(data)
                    if not valid_cache_row(provider, status, decoded, fetched, version):
                        continue
                except (ValueError, TypeError, OverflowError):
                    continue
                self.rows[provider, email] = dict(status=status, data=decoded, fetched_at=fetched, schema_version=version)
        except (sqlite3.Error, ValueError):
            self.close()
            raise ValueError('別の --outdir を使うか cache.sqlite を移してください') from None

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None

    def usable(self, provider, email):
        row = self.rows.get((provider, email))
        return row if row and row['schema_version'] == SCHEMA_VERSION else None

    def save(self, provider, email, status, data):
        with self.lock:
            old = self.usable(provider, email)
            if status == 'error' and data['kind'] == 'transient' and old and old['status'] == 'ok':
                return
            fetched = now_utc().astimezone(dt.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
            self.db.execute('INSERT OR REPLACE INTO results VALUES (?,?,?,?,?,?)',
                            (provider, email, status, json.dumps(data, ensure_ascii=False, separators=(',', ':')), fetched, SCHEMA_VERSION))
            self.db.commit()
            self.rows[provider, email] = dict(status=status, data=data, fetched_at=fetched, schema_version=SCHEMA_VERSION)


def expired(row, current, age):
    fetched = dt.datetime.fromisoformat(row['fetched_at'].replace('Z', '+00:00'))
    return current - fetched >= dt.timedelta(days=age)


def needs_query(row, args, current):
    return (args.refresh or row is None or
            row['status'] == 'ok' and expired(row, current, args.max_age) or
            row['status'] == 'error' and row['data']['kind'] == 'transient')


def query_url(provider, email):
    encoded = urllib.parse.quote(email, safe='')
    return dict(hibp=f'https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}?truncateResponse=true',
                leakcheck=f'https://leakcheck.io/api/public?check={encoded}',
                hudsonrock=f'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={encoded}',
                xon=f'https://api.xposedornot.com/v1/check-email/{encoded}')[provider]


def masked(email):
    local, domain = email.split('@', 1)
    return local[:2 if len(local) > 2 else 1] + '***@' + domain


def run_workers(args, emails, active, intervals, key, cache, current, notes, queried_now=None):
    stop = threading.Event()
    state_lock = threading.Lock()
    states = {}

    def interrupt():
        with state_lock:
            stop.set()
            for state in states.values():
                if not state['finished']:
                    state['interrupted'] = True

    def worker(provider, todo):
        state = states[provider]
        with state_lock:
            state['running'] = True
        headers = {'user-agent': f'email-breach-audit/{__version__}'}
        catalog_headers = headers.copy()
        if provider == 'hibp':
            headers['hibp-api-key'] = key
        catalog = {}
        refetched = False
        try:
            if stop.is_set():
                return
            if provider in CATALOGS:
                state['catalog'] = True
                kind, reason, payload = request_with_retry(provider, CATALOGS[provider], catalog_headers, stop, True)
                if kind == 'interrupted' or stop.is_set():
                    interrupt()
                    return
                if kind != 'ok':
                    notes[provider].append(f'停止: カタログを取得できない（{reason}）')
                    return
                catalog = catalog_map(provider, payload)
            for index, email in enumerate(todo, 1):
                if stop.is_set():
                    break
                state['catalog'] = False
                kind, reason, payload = request_with_retry(provider, query_url(provider, email), headers, stop)
                if kind == 'interrupted':
                    interrupt()
                    break
                if kind in ('fatal', 'limit'):
                    notes[provider].append(f'停止: {index} / {len(todo)} 件目で上限に達した。時間をおいて再実行すると続きから進みます' if kind == 'limit' else f'停止: {reason}')
                    break
                if kind == 'ok':
                    if provider in CATALOGS and not refetched and not stop.is_set():
                        names = [s['Name'] for s in payload] if provider == 'hibp' else ([] if payload.get('Error') == 'Not found' else [name for group in payload['breaches'] for name in group])
                        if any(name not in catalog for name in names):
                            refetched = True
                            try:
                                ck, _, cp = request_with_retry(provider, CATALOGS[provider], catalog_headers, stop, True)
                                if ck == 'ok':
                                    catalog = catalog_map(provider, cp)
                                elif ck == 'interrupted':
                                    interrupt()
                            except KeyboardInterrupt:
                                interrupt()
                    data = normalize(provider, payload, catalog)
                    status = 'ok'
                    count = data['extra']['infections'] if provider == 'hudsonrock' else len(data['sources'])
                    result = f'{count} 件' if data['found'] else 'なし'
                else:
                    status = 'error'
                    data = dict(kind=kind, reason=reason)
                    result = f'エラー {kind} {reason}'
                cache.save(provider, email, status, data)
                if queried_now is not None:
                    queried_now.add((provider, email))
                state['completed'] += 1
                log(f'[{provider}] {index}/{len(todo)} {email if args.verbose else masked(email)}: {result}')
                if index < len(todo) and not stop.is_set() and sleep(intervals[provider], stop):
                    interrupt()
                    break
        except KeyboardInterrupt:
            interrupt()
        except Exception as exc:
            notes[provider].append(f'停止: 内部エラー {type(exc).__name__}')
        finally:
            with state_lock:
                state['running'] = False
                state['finished'] = True
            if state['interrupted']:
                notes[provider].append('中断（照会前）' if state['catalog'] else f'中断（{len(todo)} 件中 {state["completed"]} 件を完了）')
            for note in notes[provider]:
                log(f'[{provider}] {note}')

    threads = []
    for provider in active:
        todo = [email for email in emails if needs_query(cache.usable(provider, email), args, current)]
        log(f'[{provider}] 照会する件数 {len(todo)}・キャッシュを使う件数 {len(emails)-len(todo)}・所要時間の目安 {format_duration(len(todo)*intervals[provider])}')
        if todo:
            states[provider] = dict(running=False, finished=False, interrupted=False, completed=0, catalog=True)
            threads.append(threading.Thread(target=worker, args=(provider, todo)))
    for thread in threads:
        try:
            if stop.is_set():
                break
            thread.start()
        except KeyboardInterrupt:
            interrupt()
            break
    threads = [thread for thread in threads if thread.ident is not None]
    while any(thread.is_alive() for thread in threads):
        try:
            for thread in threads:
                thread.join(timeout=0.1)
        except KeyboardInterrupt:
            interrupt()
    for provider, state in states.items():
        if not state['finished'] and state['interrupted']:
            notes[provider].append('中断（照会前）')
            log(f'[{provider}] 中断（照会前）')
    return stop.is_set()


def merge_key(name):
    lowered = name.lower()
    value = lowered
    while True:
        next_value = re.sub(r'\([^()]*\)|（[^（）]*）', '', value)
        if next_value == value:
            break
        value = next_value
    value = value.strip()
    for suffix in ('.co.jp', '.com', '.net', '.org', '.io', '.me', '.jp', '.co', '.ru', '.de', '.in'):
        if value.endswith(suffix):
            value = value[:-len(suffix)]
            break
    value = re.sub('[^a-z0-9]', '', value)
    return value or re.sub('[^a-z0-9]', '', lowered) or lowered


def merged_sources(records):
    merged = []
    precision_order = dict(unknown=0, year=1, month=2, day=3)
    for provider in PROVIDERS:
        rec = records.get(provider)
        if not rec or rec['status'] != 'ok':
            continue
        for source in rec['data']['sources']:
            date = compare_date(source['breach_date'], source['breach_date_precision'])
            candidates = []
            for index, existing in enumerate(merged):
                other = compare_date(existing['breach_date'], existing['breach_date_precision'])
                if merge_key(source['name']) == merge_key(existing['name']) and provider not in existing['providers'] and (date is None or other is None or abs(date.year-other.year) <= 1):
                    candidates.append((abs((date-other).days) if date and other else math.inf, index, existing))
            if not candidates:
                merged.append(dict(source, data=list(source['data']), flags=list(source['flags']), providers=[provider]))
                continue
            _, _, target = min(candidates, key=lambda item: item[:2])
            target['providers'].append(provider)
            old_precision = precision_order[target['breach_date_precision']]
            new_precision = precision_order[source['breach_date_precision']]
            if new_precision > old_precision or new_precision == old_precision and date and date > compare_date(target['breach_date'], target['breach_date_precision']):
                target['breach_date'], target['breach_date_precision'] = source['breach_date'], source['breach_date_precision']
            target['added_date'] = max(target['added_date'], source['added_date'])
            target['data'] = sorted(set(target['data']) | set(source['data']), key=lambda v: (v.lower(), v))
            target['flags'] = [f for f in FLAGS if f in target['flags'] or f in source['flags']]
            target['has_password'] = True if target['has_password'] is True or source['has_password'] is True else False if target['has_password'] is False or source['has_password'] is False else None
            target['catalog_miss'] = target['catalog_miss'] and source['catalog_miss']
    leakcheck = records.get('leakcheck')
    password_field = bool(leakcheck and leakcheck['status'] == 'ok' and leakcheck['data']['extra'].get('password_field'))
    for item in merged:
        item['data'] = sorted(set(item['data']), key=lambda v: (v.lower(), v))
        if item['has_password'] is None and 'leakcheck' in item['providers'] and password_field:
            item['has_password'] = 'maybe'
    return merged


def effective(source):
    breach = compare_date(source['breach_date'], source['breach_date_precision'])
    added = compare_date(source['added_date'], 'day')
    if added and (not breach or added > breach):
        return source['added_date'], added, 'day'
    return source['breach_date'], breach, source['breach_date_precision']


def build_rows(args, emails, active, cache, cutoff):
    summaries, findings, details = [], [], {}
    for email in emails:
        records = {p: cache.usable(p, email) for p in active}
        states = {p: 'skipped' if p not in active else records[p]['status'] if records[p] else 'not_queried' for p in args.providers}
        sources = merged_sources(records)
        for index, source in enumerate(sources):
            value, day, precision = effective(source)
            source.update(effective_date=value, effective_day=day, effective_precision=precision,
                          recent=day is None or day >= cutoff, in_scope='fabricated' not in source['flags'], index=index)
        sources.sort(key=lambda s: (-(s['effective_day'].toordinal()) if s['effective_day'] else math.inf, s['name'].lower(), s['index']))
        password = [s for s in sources if s['in_scope'] and s['has_password'] is not False]
        recent = [s for s in password if s['recent']]
        undated = [s for s in password if s['effective_day'] is None]
        stealer = [s for s in sources if s['in_scope'] and 'stealer_log' in s['flags']]
        hr = records.get('hudsonrock')
        extra = hr['data']['extra'] if hr and hr['status'] == 'ok' else {}
        coverage = 'complete' if all(states[p] == 'ok' for p in active) else 'partial'
        risk = 'critical' if extra.get('infections', 0) >= 1 or stealer else 'high' if recent else 'medium' if password else 'low' if sources else 'none' if coverage == 'complete' else 'unknown'
        dated = [s for s in sources if s['effective_day']]
        latest = max(dated, key=lambda s: (s['effective_day'], dict(day=3, month=2, year=1, unknown=0)[s['effective_precision']]))['effective_date'] if dated else ''
        row = dict(email=email, risk=risk, risk_label=RISKS[risk], coverage=coverage,
                   breaches=len(sources), password_breaches=len(password), recent_password_breaches=len(recent),
                   undated_password_breaches=len(undated), stealer_log_breaches=len(stealer), latest_breach=latest,
                   infostealer_infections=extra.get('infections', ''), infostealer_latest=(extra.get('compromised_dates') or [''])[-1],
                   breach_names='; '.join(s['name'] for s in sources))
        for state in ('ok', 'error', 'not_queried', 'skipped'):
            row['providers_' + state] = ' '.join(p for p in args.providers if states[p] == state)
        summaries.append(row)
        address_findings = []
        for source in sources:
            finding = dict(email=email, risk=risk, breach=source['name'],
                           breach_date=source['breach_date'], breach_date_precision=source['breach_date_precision'],
                           added_date=source['added_date'], effective_date=source['effective_date'],
                           recent=source['recent'], in_scope=source['in_scope'], has_password=source['has_password'],
                           flags='; '.join(source['flags']), catalog_miss=source['catalog_miss'],
                           providers=' '.join(source['providers']), data_classes='; '.join(source['data']))
            findings.append(finding)
            address_findings.append(finding)
        details[email] = (extra, address_findings, states)
    return summaries, findings, details


def text_value(value):
    if value is None:
        return ''
    if type(value) is bool:
        return 'true' if value else 'false'
    return str(value)


def csv_text(columns, rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream)
    writer.writerow(columns)
    for row in rows:
        values = [text_value(row[col]) for col in columns]
        writer.writerow(["'" + value if value.startswith(('=', '+', '-', '@', '\t', '\r')) else value for value in values])
    return stream.getvalue()


def local_time(value):
    local = value.astimezone()
    offset = local.strftime('%z')
    return local.strftime('%Y-%m-%d %H:%M') + f' (UTC{offset[:3]}:{offset[3:]})'


DATA_LABELS = {'Email addresses': 'メールアドレス',
 'Passwords': 'パスワード',
 'Usernames': 'ユーザー名',
 'Names': '氏名',
 'Phone numbers': '電話番号',
 'Physical addresses': '住所',
 'Dates of birth': '生年月日',
 'Genders': '性別',
 'IP addresses': 'IP アドレス',
 'Geographic locations': '位置情報',
 'Job titles': '役職',
 'Employers': '勤務先',
 'Social media profiles': 'SNS のプロフィール',
 'Website activity': 'サイトでの行動履歴',
 'Device information': '端末の情報',
 'Credit cards': 'クレジットカード',
 'Partial credit card data': 'クレジットカードの一部',
 'Security questions and answers': '秘密の質問と答え',
 'Auth tokens': '認証トークン',
 'Avatars': 'プロフィール画像',
 'Spoken languages': '使用言語',
 'Education levels': '学歴',
 'Browser user agent details': 'ブラウザの情報',
 'Purchases': '購入履歴',
 'Private messages': '個人宛てのメッセージ',
 'Government issued IDs': '公的な身分証'}
RISK_WORDS = {'critical': ['情報窃取マルウェアの記録がある',
              'インフォスティーラーの感染記録が <infections> 件ある、または情報窃取マルウェア由来の流出元が <stealer_log_breaches> '
              '件ある（当てはまる方だけを書く。両方なら両方を `。` でつなぐ）',
              '当日中に端末を調べる（事後対応の仕様 §5）'],
 'high': ['パスワードを含む、直近の流出がある',
          'パスワードを含む（可能性を含む）流出元のうち、<基準日> 以降または日付不明のものが <recent_password_breaches> 件ある',
          'パスワードの使い回しと変更時期を確かめる（事後対応の仕様 §5）'],
 'medium': ['パスワードを含む流出があるが、どれも古い',
            'パスワードを含む（可能性を含む）流出元が <password_breaches> 件あるが、どれも <基準日> より前',
            'パスワードの使い回しと変更時期を確かめる（事後対応の仕様 §5）'],
 'low': ['流出はあるが、パスワードを含まない',
         '流出元が <breaches> 件あるが、パスワードを含むものはない（作られたデータの疑いがあるものだけの場合を含む）',
         'アドレスの流出を確かめる（事後対応の仕様 §5）'],
 'none': ['どの照会先でも見つからなかった', '（§10.5 の 6 の表に入るので、文は書かない）', 'なし'],
 'unknown': ['照会できなかった照会先があり、判断できない',
             '流出元は見つかっていないが、<照会状態が ok でない照会先の名称を `、` でつなぐ> で照会できていない',
             '時間をおいて再実行する。それまでは未確認として扱う（事後対応の仕様 §5 の R5）']}
def render_html(args, summaries, details, active, cache, notes, current, cutoff):
    esc = lambda value: html.escape(text_value(value), quote=True)
    states_labels = dict(ok='照会済み', error='エラー', not_queried='未照会', skipped='照会しなかった')
    flag_labels = dict(stealer_log='情報窃取マルウェア由来', spam_list='スパム用リスト', fabricated='作られたデータの疑い（判定に使わない）', unverified='未検証', malware='マルウェア関連')
    def table(headers, rows):
        return '<table><thead><tr>' + ''.join('<th scope="col">'+esc(v)+'</th>' for v in headers) + '</tr></thead><tbody>' + ''.join('<tr>'+''.join('<td>'+esc(v)+'</td>' for v in row)+'</tr>' for row in rows) + '</tbody></table>'
    def pairs(rows):
        return '<table class="overview"><tbody>'+''.join('<tr><th scope="row">'+esc(k)+'</th><td>'+esc(v)+'</td></tr>' for k,v in rows)+'</tbody></table>'
    counts = collections.Counter(r['risk'] for r in summaries)
    partial = sum(r['coverage'] == 'partial' for r in summaries)
    parts = ['<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>メールアドレス流出調査レポート</title>',
    '''<style>
:root{color-scheme:light dark;--bg:#f4f6f8;--paper:#fff;--ink:#202b38;--line:#c6ced7;--muted:#edf1f5;--accent:#245e92}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.7 system-ui,sans-serif}main{max-width:1200px;margin:auto;padding:32px}h1{font-size:28px}h2{margin-top:36px;border-bottom:2px solid var(--line);padding-bottom:8px}h3{overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;margin:16px 0;background:var(--paper);table-layout:fixed}th,td{border:1px solid var(--line);padding:9px;vertical-align:top;text-align:left;overflow-wrap:anywhere}th{background:var(--muted);font-weight:600}.overview th{width:32%}.addr{background:var(--paper)}section.addr{padding:20px;margin:24px 0;border:1px solid var(--line);border-left:6px solid var(--accent)}[data-risk="critical"]{--accent:#b42332}[data-risk="high"]{--accent:#b65d00}[data-risk="medium"]{--accent:#806300}[data-risk="low"]{--accent:#245e92}[data-risk="unknown"]{--accent:#755197}section.addr h3{color:var(--accent)}button,input{font:inherit;padding:8px 12px;margin:4px;border:1px solid var(--line);border-radius:4px;background:var(--paper);color:var(--ink)}button[aria-pressed="true"]{outline:2px solid var(--accent)}input{max-width:100%}.notice{padding:12px;background:var(--muted)}
@media(prefers-color-scheme:dark){:root{--bg:#171d25;--paper:#202935;--ink:#e5ebf2;--line:#526070;--muted:#2d3948;--accent:#84bcec}section.addr h3{color:var(--ink)}}
@page{size:A4 portrait;margin:15mm}@media print{:root{color-scheme:light;--bg:white;--paper:white;--ink:black;--line:#888;--muted:#eee}body{font-size:9pt}main{padding:0;max-width:none}.filters{display:none}.addr[hidden]{display:revert!important}section.addr{padding:10px;break-inside:auto}th,td{padding:4px}thead{display:table-header-group}tr{break-inside:avoid}h2,h3{break-after:avoid}a{color:black}table{width:100%}}
</style></head><body><main>''', '<h1>メールアドレス流出調査レポート</h1>']
    parts.append(pairs([('作成日時',local_time(current)),('対象のアドレス数',len(summaries)),('照会先','、'.join(NAMES[p] for p in active)),('照会しなかった照会先','／'.join(NAMES[p]+': '+notes[p][0].removeprefix('スキップ: ') for p in args.providers if p not in active) or 'なし'),('直近とみなす期間',f'{cutoff} 以降'),('実行の種類','キャッシュのみ' if args.report_only else '通常')]))
    parts += ['<h2>結果の要約</h2>',table(['区分','件数','意味','最初にすること'],[[label,counts[risk],RISK_WORDS[risk][0],RISK_WORDS[risk][2]] for risk,label in RISKS.items()]),f'<p>照会できなかった照会先があるアドレス: {partial} 件</p>','<h2>照会先ごとの状況</h2>']
    provider_rows=[]
    for provider in args.providers:
        used=[cache.usable(provider,r['email']) for r in summaries] if provider in active else []
        used=[r for r in used if r]
        times=sorted(dt.datetime.fromisoformat(r['fetched_at'].replace('Z','+00:00')) for r in used)
        span=local_time(times[0])+'〜'+local_time(times[-1]) if times else '—'
        provider_rows.append([NAMES[provider],CONFIRMATION[provider],*[sum(details[r['email']][2][provider]==state for r in summaries) for state in states_labels],span,sum(r['status']=='ok' and expired(r,current,args.max_age) for r in used),'／'.join(notes[provider]) or '—'])
    parts.append(table(['照会先','確認の状態','照会済み','エラー','未照会','照会しなかった','結果の取得日時','古い結果','備考'],provider_rows))
    parts.append('<div class="filters" role="group" aria-label="絞り込み">'+''.join(f'<button type="button" data-filter="{risk}" aria-pressed="false">{label}</button>' for risk,label in RISKS.items())+'<button type="button" data-filter="" aria-pressed="true">すべて</button><label>検索 <input id="search" type="search" placeholder="アドレス・流出元"></label></div><h2>アドレスごとの結果</h2>')
    ordered=sorted(enumerate(summaries),key=lambda pair:(list(RISKS).index(pair[1]['risk']),-pair[1]['breaches'],pair[0]))
    for _,r in ordered:
        if r['risk']=='none': continue
        extra,findings,states=details[r['email']]
        risk=r['risk']
        reason=RISK_WORDS[risk][1]
        if risk=='critical':
            reason='。'.join(([f'インフォスティーラーの感染記録が {extra["infections"]} 件ある'] if extra.get('infections',0) else [])+([f'情報窃取マルウェア由来の流出元が {r["stealer_log_breaches"]} 件ある'] if r['stealer_log_breaches'] else []))
        else:
            for key in ('recent_password_breaches','password_breaches','breaches'):
                reason=reason.replace('<'+key+'>',str(r[key]))
            reason=reason.replace('<基準日>',str(cutoff))
            if risk=='unknown':
                reason='流出元は見つかっていないが、'+'、'.join(NAMES[p] for p in args.providers if states[p]!='ok')+' で照会できていない'
        parts.append(f'<section class="addr" data-risk="{risk}" data-search="{esc(r["email"]+" "+r["breach_names"])}"><h3>{esc(RISKS[risk]+" "+r["email"])}</h3><p>{esc(reason)}</p>')
        parts.append(pairs([('流出元の数',r['breaches']),('パスワードを含む（可能性を含む）流出元の数',r['password_breaches']),('そのうち直近の数',r['recent_password_breaches']),('最新の流出日',r['latest_breach'] or '—'),('照会先ごとの照会状態','／'.join(NAMES[p]+': '+states_labels[states[p]] for p in args.providers))]))
        if states.get('hudsonrock')=='ok':
            parts.append('<h4>インフォスティーラー</h4>'+pairs([('感染の記録の件数',extra['infections']),('最新の感染日',(extra['compromised_dates'] or ['—'])[-1]),('感染した端末にあった社内サービスの認証情報の数',extra['corporate_services']),('個人向けサービスの認証情報の数',extra['user_services'])]))
        rows=[]
        for f in findings:
            caution=[flag_labels[flag] for flag in f['flags'].split('; ') if flag]
            if f['catalog_miss']: caution.append('照会先の一覧に詳細なし')
            password='含む' if f['has_password'] is True else '含まない' if f['has_password'] is False else '含む可能性あり' if f['has_password']=='maybe' else '不明（含むとして扱う）'
            rows.append([f['breach'],f['breach_date'] or '不明',f['added_date'] or '不明',('はい' if f['recent'] else 'いいえ') if f['effective_date'] else '日付不明（直近として扱う）','、'.join(DATA_LABELS.get(v,v) for v in f['data_classes'].split('; ') if v) or '不明',password,'、'.join(caution),'、'.join(NAMES[p] for p in f['providers'].split())])
        if rows: parts.append(table(['流出元','流出日','公開日','直近か','漏れた情報','パスワード','注意','検出した照会先'],rows))
        parts.append('</section>')
    parts.append('<h2>検出なしのアドレス</h2>')
    none=[r for r in summaries if r['risk']=='none']
    if none:
        parts.append('<table><thead><tr><th>アドレス</th><th>照会先</th></tr></thead><tbody>')
        for r in none:
            parts.append(f'<tr class="addr" data-risk="none" data-search="{esc(r["email"])}"><td>{esc(r["email"])}</td><td>{esc("、".join(NAMES[p] for p in r["providers_ok"].split()))}</td></tr>')
        parts.append('</tbody></table>')
    else: parts.append('<p>なし</p>')
    conditions=['感染の記録がある、または判定対象に情報窃取マルウェア由来の流出元がある','パスワードを含む（可能性・不明を含む）、直近の判定対象の流出元がある','パスワードを含む（可能性・不明を含む）判定対象の流出元がある','流出元がある（作られたデータの疑いを含む）','流出元がなく、有効な照会先すべてで照会済み','流出元がなく、有効な照会先に照会済みでないものがある']
    parts+=['<h2>区分の決め方と注意</h2><p>上から順に最初に当てはまった区分にします。直近は基準日以降の有効日（流出日と公開日の新しい方）で、日付不明も含みます。作られたデータの疑いがある流出元は判定対象から除きます。</p>',table(['区分','条件'],zip(RISKS.values(),conditions)),'<p class="notice">検出は侵害を意味しない。対応は事後対応の手順に従う</p><p class="notice">このファイルは個人情報を含む。共有の範囲に注意する</p>']
    if 'leakcheck' in active: parts.append('<p><a href="https://leakcheck.io">Powered by LeakCheck</a></p>')
    parts.append('''</main><script>
let selectedRisk = '';
function filterRows(){const query=document.getElementById('search').value.toLowerCase();document.querySelectorAll('.addr').forEach(row=>{row.hidden=Boolean((selectedRisk && row.dataset.risk!==selectedRisk)||!row.dataset.search.toLowerCase().includes(query));});}
document.getElementById('search').addEventListener('input',filterRows);
document.querySelectorAll('[data-filter]').forEach(button=>button.addEventListener('click',()=>{selectedRisk=button.dataset.filter;document.querySelectorAll('[data-filter]').forEach(b=>b.setAttribute('aria-pressed',String(b===button)));filterRows();}));
</script></body></html>''')
    return '\n'.join(parts)


def json_text(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def utc_text(value):
    return value.astimezone(dt.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def write_outputs(outdir, contents, record_contents, current):
    paths = []
    record_tmp = None
    interrupted = False
    runs = outdir / 'runs'
    try:
        for name, body, encoding in contents:
            fd, tmp = tempfile.mkstemp(prefix='.' + name + '-', dir=outdir)
            paths.append((Path(tmp), outdir / name))
            with os.fdopen(fd, 'w', encoding=encoding, newline='') as stream:
                stream.write(body)
            Path(tmp).chmod(0o600)
        runs.mkdir(mode=0o700, exist_ok=True)
        runs.chmod(0o700)
        record_tmp = Path(tempfile.mkdtemp(prefix='.tmp-', dir=runs))
        record_tmp.chmod(0o700)
        base = current.astimezone().strftime('%Y%m%d-%H%M%S')
        destination = runs / base
        suffix = 2
        while destination.exists():
            destination = runs / f'{base}-{suffix}'
            suffix += 1
        # finished_at is sampled immediately before writing the record.
        record_contents['run.json']['finished_at'] = utc_text(now_utc())
        for name, body, encoding in contents + [
                ('results.jsonl', record_contents['results.jsonl'], 'utf-8'),
                ('run.json', json_text(record_contents['run.json']), 'utf-8')]:
            path = record_tmp / name
            with path.open('w', encoding=encoding, newline='') as stream:
                stream.write(body)
            path.chmod(0o600)
        # Once rename begins, finish every replacement, including after an
        # interrupt delivered between operations or after an operation succeeds.
        index = 0
        while index <= len(paths):
            try:
                while index <= len(paths):
                    if index == 0:
                        if record_tmp.exists():
                            os.rename(record_tmp, destination)
                    else:
                        tmp, target = paths[index - 1]
                        if tmp.exists():
                            os.replace(tmp, target)
                    index += 1
            except KeyboardInterrupt:
                interrupted = True
                record_contents['run.json']['exit_code'] = 130
                record_path = (destination if destination.exists() else record_tmp) / 'run.json'
                # Retry if another Ctrl+C arrives while updating the recorded code.
                while True:
                    try:
                        record_path.write_text(json_text(record_contents['run.json']), encoding='utf-8')
                        record_path.chmod(0o600)
                        break
                    except KeyboardInterrupt:
                        continue
        return interrupted, destination
    finally:
        for tmp, _ in paths:
            tmp.unlink(missing_ok=True)
        if record_tmp is not None and record_tmp.exists():
            shutil.rmtree(record_tmp)


def execute(args, current, today):
    intervals = dict(hibp=6.2, leakcheck=1.1, hudsonrock=1.5, xon=145.0)
    for provider, variable, default in (('hibp', 'HIBP_RPM', '10'), ('xon', 'XON_INTERVAL', '145')):
        if provider in args.providers:
            try:
                value = float(os.environ.get(variable, default))
                if not math.isfinite(value) or value <= 0:
                    raise ValueError
            except ValueError:
                log(f'{variable}: 有限の正の数を指定してください')
                return 2
            intervals[provider] = 60 / value + 0.2 if provider == 'hibp' else value
    key = os.environ.get('HIBP_API_KEY', '').strip()
    try:
        emails = read_input(args)
    except (OSError, UnicodeError):
        log('入力ファイルを読み込めません')
        return 2
    if not emails:
        log('メールアドレスが見つかりませんでした')
        return 2
    outdir = Path(args.outdir).expanduser().absolute()
    cache = None
    notes = {p: [] for p in args.providers}
    try:
        if args.report_only:
            try:
                cache = Cache(outdir / 'cache.sqlite', readonly=True)
            except ValueError as exc:
                log(str(exc))
                return 2
        active = []
        for provider in args.providers:
            reason = ('キャッシュに使える結果がない' if not any(cache.usable(provider, email) for email in emails) else '') if args.report_only else ('HIBP_API_KEY が未設定' if provider == 'hibp' and not key else '')
            if reason:
                notes[provider].append('スキップ: ' + reason)
                log(f'[{provider}] スキップ: {reason}')
            else:
                active.append(provider)
        log('有効なプロバイダ: ' + ' '.join(active))
        if not active:
            return 2
        try:
            outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError:
            log('出力ディレクトリを作れません')
            return 2
        if outdir.stat().st_mode & 0o044:
            log('警告: 出力ディレクトリをグループまたは他人が読めます')
        if not args.report_only:
            try:
                cache = Cache(outdir / 'cache.sqlite')
            except ValueError as exc:
                log(str(exc))
                return 2
        interrupted = False
        queried_now = set()
        if args.report_only:
            for provider in active:
                log(f'[{provider}] 使える結果の件数 {sum(bool(cache.usable(provider, email)) for email in emails)}')
        else:
            interrupted = run_workers(args, emails, active, intervals, key, cache, current, notes, queried_now)
        try:
            cutoff = today.replace(year=today.year-args.recent_years)
        except ValueError:
            cutoff = dt.date(today.year-args.recent_years, 2, 28)
        summaries, findings, details = build_rows(args, emails, active, cache, cutoff)
        contents = [('summary.csv', csv_text(SUMMARY, summaries), 'utf-8-sig'),
                    ('findings.csv', csv_text(FINDINGS, findings), 'utf-8-sig'),
                    ('report.html', render_html(args, summaries, details, active, cache, notes, current, cutoff), 'utf-8')]
        counts = collections.Counter(r['risk'] for r in summaries)
        partial = sum(r['coverage'] == 'partial' for r in summaries)
        code = 130 if interrupted else 3 if partial else 0
        result_lines = []
        for email in emails:
            for provider in args.providers:
                used = cache.usable(provider, email) if provider in active else None
                result_lines.append(json_text(dict(
                    email=email, provider=provider, state=details[email][2][provider],
                    fetched_at=used['fetched_at'] if used else None,
                    queried_now=(provider, email) in queried_now,
                    result=used['data'] if used and used['status'] == 'ok' else None,
                    error=used['data'] if used and used['status'] == 'error' else None)))
        run = dict(tool_version=__version__, started_at=utc_text(current), finished_at=None,
                   mode='report_only' if args.report_only else 'normal', input_file=Path(args.input).name,
                   addresses=len(emails),
                   options=dict(providers=args.providers, max_age=args.max_age, refresh=args.refresh,
                                recent_years=args.recent_years, limit=args.limit),
                   effective_providers=active,
                   skipped_providers={p: notes[p][0].removeprefix('スキップ: ') for p in args.providers if p not in active},
                   provider_notes={p: '／'.join(notes[p]) for p in args.providers if notes[p]},
                   risk_counts={risk: counts[risk] for risk in RISKS}, partial=partial, exit_code=code)
        output_interrupted, record_path = write_outputs(
            outdir, contents, {'results.jsonl': '\n'.join(result_lines) + '\n', 'run.json': run}, current)
        interrupted = output_interrupted or interrupted
        for name in ('cache.sqlite', 'summary.csv', 'findings.csv', 'report.html'):
            path = outdir / name
            if path.exists():
                path.chmod(0o600)
        counts = collections.Counter(r['risk'] for r in summaries)
        partial = sum(r['coverage'] == 'partial' for r in summaries)
        code = 130 if interrupted else 3 if partial else 0
        log(' ／ '.join(f'{label}: {counts[risk]}' for risk, label in RISKS.items()) + f' ／ 照会できなかった照会先があるアドレス: {partial}')
        for name in ('summary.csv', 'findings.csv', 'report.html'):
            log(str(outdir / name))
        log(str(record_path))
        log(f'終了コード: {code}')
        return code
    finally:
        if cache:
            cache.close()


def main(argv: list[str] | None = None) -> int:
    previous_umask = os.umask(0o077)
    try:
        current = now_utc()
        today = today_local()
        try:
            args = parse_args(argv)
        except SystemExit as exc:
            return int(exc.code)
        return execute(args, current, today)
    except KeyboardInterrupt:
        log('中断')
        return 130
    except Exception as exc:
        log(f'内部エラー {type(exc).__name__}')
        return 1
    finally:
        os.umask(previous_umask)


if __name__ == '__main__':
    sys.exit(main())
