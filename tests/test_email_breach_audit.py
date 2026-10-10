"""SPEC v0.14 §14: acceptance checks through the public injection points."""
import contextlib
import csv
import datetime as dt
from html.parser import HTMLParser
import io
import http.client
import sys
import threading
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import email_breach_audit as audit

UTC_NOW = dt.datetime(2026, 10, 10, 3, 15, tzinfo=dt.timezone.utc)
SCHEMA = ('CREATE TABLE results(provider TEXT, email TEXT, status TEXT, data TEXT, '
          'fetched_at TEXT, schema_version INTEGER, PRIMARY KEY(provider,email))')


def reply(body, status=200, headers=None):
    return status, headers or {}, json.dumps(body).encode()


def source(name='Example', date='', precision='unknown', password=None, added='', flags=None):
    return dict(name=name, breach_date=date, breach_date_precision=precision,
                added_date=added, data=[], has_password=password,
                flags=flags or [], catalog_miss=False)


def record(sources=None, extra=None):
    return dict(found=bool(sources or extra), sources=sources or [], extra=extra if extra is not None else {'fields': [], 'password_field': False})


class AddressCounter(HTMLParser):
    def __init__(self):
        super().__init__()
        self.count = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('tr', 'section') and 'addr' in dict(attrs).get('class', '').split():
            self.count += 1


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.input = self.root / 'input.txt'
        self.out = self.root / 'output'
        self.input.write_text('taro@example.com\n', encoding='utf-8')
        self.calls = []
        self.waits = []
        self.stderr = ''
        self.stdout = ''

    def run_audit(self, handler=None, options=(), env=None, providers='leakcheck'):
        def http(url, headers, timeout):
            self.calls.append(url)
            self.assertEqual(timeout, 30)
            self.assertEqual(headers['user-agent'], 'email-breach-audit/0.1.0')
            return handler(url, headers, timeout) if handler else reply({'success': True, 'sources': []})

        def wait(seconds, stop):
            self.waits.append(seconds)
            return False

        err, out = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, env or {}, clear=True), \
                patch.object(audit, 'http_get', side_effect=http), \
                patch.object(audit, 'sleep', side_effect=wait), \
                patch.object(audit, 'now_utc', return_value=UTC_NOW), \
                patch.object(audit, 'today_local', return_value=dt.date(2026, 10, 10)), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            code = audit.main([str(self.input), '-o', str(self.out),
                               '--providers', providers, *options])
        self.stderr, self.stdout = err.getvalue(), out.getvalue()
        return code

    def rows(self, name='summary.csv'):
        with (self.out / name).open(encoding='utf-8-sig', newline='') as stream:
            return list(csv.DictReader(stream))

    def html(self):
        return (self.out / 'report.html').read_text(encoding='utf-8')

    def seed(self, rows):
        self.out.mkdir(exist_ok=True)
        with contextlib.closing(sqlite3.connect(self.out / 'cache.sqlite')) as db:
            db.execute(SCHEMA)
            for provider, email, status, data, fetched, version in rows:
                db.execute('INSERT INTO results VALUES (?,?,?,?,?,?)',
                           (provider, email, status, json.dumps(data), fetched, version))
            db.commit()

    def test_a01_300_address_rows(self):
        self.input.write_text(''.join(f'user{i}@example.com\n' for i in range(300)))
        self.assertEqual(self.run_audit(lambda url, *_: reply({'success': True, 'sources': [] if int(url.split('user')[1].split('%40')[0]) % 2 else [{'name': 'Example source'}]})), 0)
        self.assertEqual(len(self.rows()), 300)
        parser = AddressCounter()
        parser.feed(self.html())
        self.assertEqual(parser.count, 300)

    def test_a02_input_statistics(self):
        self.input.write_text('\ufeff # comment\r\nA@example.com,a@example.com\r'
                              'header\n\n b@example.org\nno address\n', encoding='utf-8')
        self.assertEqual(self.run_audit(options=['--limit', '1']), 0)
        self.assertEqual(self.stderr.splitlines()[0],
                         '入力: 行 5 / 抽出 3 / 重複除外後 2 / アドレスなし 2 / 処理 1')

    def test_a03_interrupt_and_resume(self):
        addresses = ['ok@example.com', 'transient@example.com', 'invalid@example.com',
                     'interrupt@example.com', 'last@example.com']
        self.input.write_text('\n'.join(addresses))
        def first(url, *_):
            if 'transient%40' in url:
                return reply({}, 503)
            if 'invalid%40' in url:
                return reply({}, 400)
            if 'interrupt%40' in url:
                raise KeyboardInterrupt
            return reply({'success': True, 'sources': []})
        self.assertEqual(self.run_audit(first), 130)
        self.assertIn('中断（5 件中 3 件を完了）', self.html())
        self.calls.clear()
        self.assertEqual(self.run_audit(), 3)
        self.assertEqual(self.calls, [f'https://leakcheck.io/api/public?check={name}%40example.com'
                                      for name in ('transient', 'interrupt', 'last')])

    def test_a04_missing_hibp_key_skips_only_hibp(self):
        self.assertEqual(self.run_audit(providers='hibp,leakcheck'), 0)
        self.assertEqual(self.rows()[0]['providers_skipped'], 'hibp')
        self.assertIn('スキップ: HIBP_API_KEY が未設定', self.html())
        self.assertEqual(len(self.calls), 1)

    def test_a05_no_active_provider_creates_no_directory(self):
        self.assertEqual(self.run_audit(providers='hibp'), 2)
        self.assertFalse(self.out.exists())
        self.assertEqual(self.run_audit(options=['--report-only']), 2)
        self.assertFalse(self.out.exists())
        self.assertEqual(self.calls, [])

    def test_a06_retry_after_waits_six_seconds(self):
        replies = iter([reply({}, 429, {'retry-after': '5'}),
                        reply({'success': True, 'sources': []})])
        self.assertEqual(self.run_audit(lambda *_: next(replies)), 0)
        self.assertEqual(self.waits, [6])

    def test_a06_headerless_rate_limit_stops(self):
        self.assertEqual(self.run_audit(lambda *_: reply({}, 429)), 3)
        self.assertEqual(self.waits, [30, 60])
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(self.rows()[0]['providers_not_queried'], 'leakcheck')

    def test_a07_invalid_is_saved_without_retry(self):
        self.assertEqual(self.run_audit(lambda *_: reply({}, 400)), 3)
        self.assertEqual(len(self.calls), 1)
        with contextlib.closing(sqlite3.connect(self.out / 'cache.sqlite')) as db:
            status, data = db.execute('SELECT status,data FROM results').fetchone()
        self.assertEqual(status, 'error')
        self.assertEqual(json.loads(data)['kind'], 'invalid')

    def test_a08_twitter_merge(self):
        catalog = [dict(Name='Twitter', Title='Twitter', BreachDate='2022-01-01', DataClasses=[]),
                   dict(Name='Twitter200M', Title='Twitter (200M)', BreachDate='2021-01-01', DataClasses=[])]
        def http(url, *_):
            if url.endswith('/breaches'):
                return reply(catalog)
            if 'breachedaccount' in url:
                return reply([{'Name': 'Twitter'}, {'Name': 'Twitter200M'}])
            return reply({'success': True, 'sources': [{'name': 'Twitter.com (scraping data)', 'date': '2022-01'}]})
        self.assertEqual(self.run_audit(http, providers='hibp,leakcheck', env={'HIBP_API_KEY': 'test-marker-key'}), 0)
        findings = self.rows('findings.csv')
        self.assertEqual(len(findings), 2)
        self.assertEqual({r['breach']: r['providers'] for r in findings},
                         {'Twitter': 'hibp leakcheck', 'Twitter (200M)': 'hibp'})

    def test_a09_risk_categories_and_boundaries(self):
        cases = [
            ('critical', source(flags=['stealer_log'])),
            ('high', source(date='2023-10-10', precision='day', password=True)),
            ('medium', source(date='2023-10-09', precision='day', password=True)),
            ('low', source(password=False)),
            ('none', None),
            ('unknown', 'error'),
            ('high', source(date='2023-10', precision='month', password=True)),
            ('medium', source(date='2023-09', precision='month', password=True)),
            ('high', source(date='2023', precision='year', password=True)),
            ('medium', source(date='2022', precision='year', password=True)),
            ('high', source(password=True)),
            ('high', source(date='2000', precision='year', password=True, added='2023-10-10')),
            ('high', source(password=None)),
            ('high', 'maybe'),
            ('low', source(password=True, flags=['fabricated'])),
            ('critical', 'infection'),
        ]
        self.input.write_text('\n'.join(f'case{i}@example.com' for i in range(len(cases))))
        seeds = []
        for i, (_, item) in enumerate(cases):
            provider, status = 'leakcheck', 'ok'
            data = record([] if item is None else [item], {'fields': [], 'password_field': False})
            if item == 'error':
                status, data = 'error', {'kind': 'invalid', 'reason': 'HTTP 400'}
            elif item == 'maybe':
                data = record([source()], {'fields': ['password'], 'password_field': True})
            elif item == 'infection':
                provider = 'hudsonrock'
                data = record(extra={'infections': 1, 'compromised_dates': [], 'corporate_services': 0, 'user_services': 0})
            seeds.append((provider, f'case{i}@example.com', status, data, '2026-10-10T03:15:00Z', 2))
        for i in range(len(cases)-1):
            seeds.append(('hudsonrock', f'case{i}@example.com', 'ok',
                          record(extra={'infections': 0, 'compromised_dates': [],
                                        'corporate_services': 0, 'user_services': 0}),
                          '2026-10-10T03:15:00Z', 2))
        self.seed(seeds)
        self.assertEqual(self.run_audit(options=['--report-only'], providers='leakcheck,hudsonrock'), 3)
        self.assertEqual([r['risk'] for r in self.rows()], [risk for risk, _ in cases])
        maybe_email = f'case{next(i for i, (_, item) in enumerate(cases) if item == "maybe")}@example.com'
        self.assertEqual([r['has_password'] for r in self.rows('findings.csv') if r['email'] == maybe_email], ['maybe'])
        self.assertEqual(self.calls, [])

    def test_a10_catalog_refetched_once(self):
        self.input.write_text('one@example.com\ntwo@example.com\n')
        def http(url, *_):
            return reply([]) if url.endswith('/breaches') else reply([{'Name': 'Missing'}])
        self.assertEqual(self.run_audit(http, providers='hibp', env={'HIBP_API_KEY': 'test-marker-key'}), 0)
        self.assertEqual(sum(url.endswith('/breaches') for url in self.calls), 2)
        self.assertEqual([r['catalog_miss'] for r in self.rows('findings.csv')], ['true', 'true'])

    def test_a11_report_only_uses_expired_not_other_schema(self):
        self.input.write_text('old@example.com\nversion@example.com\n')
        self.seed([('leakcheck', 'old@example.com', 'ok', record([source(password=False)]), '2020-01-01T00:00:00Z', 2),
                   ('leakcheck', 'version@example.com', 'ok', record([source(password=True)]), '2026-10-10T00:00:00Z', 1)])
        self.assertEqual(self.run_audit(options=['--report-only', '--max-age', '1']), 3)
        self.assertEqual([(r['risk'], r['providers_ok'], r['providers_not_queried']) for r in self.rows()],
                         [('low', 'leakcheck', ''), ('unknown', '', 'leakcheck')])
        self.assertEqual(self.calls, [])

    def test_a12_secrets_and_disallowed_fields_absent(self):
        banned = ['top_passwords', 'top_logins', 'ip', 'computer_name', 'operating_system',
                  'malware_path', 'antiviruses', 'unexpected']
        markers = ['DO_NOT_STORE_' + name for name in banned] + ['DO_NOT_STORE_message', 'DO_NOT_STORE_KEY']
        stealer = dict(zip(banned, markers))
        stealer.update(date_compromised='2025-01-01T00:00:00Z', total_corporate_services=2, total_user_services=3)
        def http(url, headers, _):
            if 'breachedaccount' in url:
                self.assertEqual(headers['hibp-api-key'], markers[-1])
                return reply({}, 404)
            if url.endswith('/breaches'):
                return reply([])
            return reply({'stealers': [stealer], 'message': markers[-2]})
        self.assertEqual(self.run_audit(http, providers='hibp,hudsonrock',
                                        env={'HIBP_API_KEY': markers[-1]}), 0)
        data = b''.join(p.read_bytes() for p in self.out.rglob('*') if p.is_file()) + self.stderr.encode()
        for marker in markers:
            self.assertNotIn(marker.encode(), data)

    def test_a13_masked_and_verbose_progress(self):
        self.input.write_text('taro@example.com\nab@example.org\n')
        self.assertEqual(self.run_audit(), 0)
        self.assertIn('[leakcheck] 1/2 ta***@example.com: なし', self.stderr)
        self.assertIn('[leakcheck] 2/2 a***@example.org: なし', self.stderr)
        self.assertNotIn('taro@example.com', self.stderr)
        self.assertEqual(self.run_audit(options=['--verbose', '--refresh']), 0)
        self.assertIn('[leakcheck] 1/2 taro@example.com: なし', self.stderr)
        self.assertIn('[leakcheck] 2/2 ab@example.org: なし', self.stderr)

    def test_a14_html_escape_and_csv_formula_guard(self):
        self.assertEqual(self.run_audit(lambda *_: reply({'success': True, 'sources': [
            {'name': '<script>alert(1)</script>'}, {'name': '=1+1'}]})), 0)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', self.html())
        self.assertNotIn('<script>alert(1)</script>', self.html())
        self.assertIn("'=1+1", [r['breach'] for r in self.rows('findings.csv')])

    def test_a15_interruption_takes_priority_over_partial(self):
        self.assertEqual(self.run_audit(lambda *_: (_ for _ in ()).throw(KeyboardInterrupt())), 130)
        self.assertEqual(self.rows()[0]['coverage'], 'partial')

    def test_a15_argument_errors_and_version_return_codes(self):
        for args in ([], ['--prov', 'hibp'], [str(self.input), '--limit', '0'],
                     [str(self.input), '--refresh', '--report-only']):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), \
                    patch.object(audit, 'http_get', side_effect=AssertionError('network forbidden')), \
                    patch.object(audit, 'sleep', side_effect=AssertionError('waiting forbidden')), \
                    patch.object(audit, 'now_utc', return_value=UTC_NOW), \
                    patch.object(audit, 'today_local', return_value=dt.date(2026, 10, 10)):
                self.assertEqual(audit.main(args), 2)
        with contextlib.redirect_stdout(io.StringIO()) as output, \
                patch.object(audit, 'http_get', side_effect=AssertionError('network forbidden')), \
                patch.object(audit, 'sleep', side_effect=AssertionError('waiting forbidden')), \
                patch.object(audit, 'now_utc', return_value=UTC_NOW), \
                patch.object(audit, 'today_local', return_value=dt.date(2026, 10, 10)):
            self.assertEqual(audit.main(['--version']), 0)
        self.assertEqual(output.getvalue(), 'email-breach-audit 0.1.0\n')

    def test_a16_unexpected_worker_exception_is_isolated(self):
        def http(url, *_):
            if 'leakcheck.io' in url:
                raise RuntimeError('DO_NOT_PRINT_RESPONSE')
            return reply({'stealers': []})
        self.assertEqual(self.run_audit(http, providers='leakcheck,hudsonrock'), 3)
        row = self.rows()[0]
        self.assertEqual(row['providers_ok'], 'hudsonrock')
        self.assertEqual(row['providers_not_queried'], 'leakcheck')
        self.assertIn('停止: 内部エラー RuntimeError', self.html())
        self.assertNotIn('DO_NOT_PRINT_RESPONSE', self.stderr + self.html())


    def test_spec_version_references_are_v014(self):
        self.assertIn('SPEC.md v0.14', audit.__doc__)
        self.assertIn('SPEC v0.14', __doc__)

    def test_progress_duration_format(self):
        self.assertEqual(audit.format_duration(6.6000000000000005), '6.6 秒')
        self.assertEqual(audit.format_duration(0), '0.0 秒')
        self.assertEqual(audit.format_duration(60), '約 1 分')
        self.assertEqual(audit.format_duration(61), '約 2 分')

    def test_http_exception_retry_and_last_reason(self):
        errors = [http.client.IncompleteRead(b'partial'), http.client.BadStatusLine('bad'), http.client.LineTooLong('line')]
        for error in errors:
            with self.subTest(error=type(error).__name__):
                self.calls.clear()
                self.waits.clear()
                self.assertEqual(self.run_audit(lambda *_: (_ for _ in ()).throw(error), options=['--refresh']), 3)
                self.assertEqual(len(self.calls), 8)
                self.assertEqual(self.waits, [5, 10, 15, 20, 25, 30, 35])
                with contextlib.closing(sqlite3.connect(self.out / 'cache.sqlite')) as db:
                    data = json.loads(db.execute('SELECT data FROM results').fetchone()[0])
                self.assertEqual(data, {'kind': 'transient', 'reason': 'network: ' + type(error).__name__})
        replies = iter([http.client.BadStatusLine('bad'), reply({'success': True, 'sources': []})])
        def recover(*_):
            value = next(replies)
            if isinstance(value, Exception):
                raise value
            return value
        self.assertEqual(self.run_audit(recover, options=['--refresh']), 0)

    def test_http_get_read_exception_propagates(self):
        response = unittest.mock.MagicMock()
        response.__enter__.return_value = response
        response.read.side_effect = http.client.IncompleteRead(b'partial')
        opener = unittest.mock.Mock()
        opener.open.return_value = response
        with patch.object(audit.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaises(http.client.IncompleteRead):
                audit.http_get(audit.CATALOGS['hibp'], {}, 30)

    def test_catalog_ok_after_stop_and_before_thread_start(self):
        for before_start in (False, True):
            with self.subTest(before_start=before_start):
                self.calls.clear()
                stop = threading.Event()
                def http(*_):
                    stop.set()
                    return reply([])
                real_event = threading.Event
                events = iter([stop])
                with patch.object(audit.threading, 'Event', side_effect=lambda: next(events, None) or real_event()):
                    if before_start:
                        with patch.object(audit.threading.Thread, 'start', side_effect=KeyboardInterrupt):
                            code = self.run_audit(http, providers='hibp', env={'HIBP_API_KEY': 'test-key'})
                    else:
                        code = self.run_audit(http, providers='hibp', env={'HIBP_API_KEY': 'test-key'})
                self.assertEqual(code, 130)
                self.assertEqual(self.calls, [] if before_start else [audit.CATALOGS['hibp']])
                self.assertIn('中断（照会前）', self.html())
                self.assertNotIn('件を完了', self.html())

    def test_output_interrupt_between_replacements_completes_all(self):
        self.assertEqual(self.run_audit(), 0)
        self.input.write_text('new@example.com')
        fired = False
        def trace(frame, event, arg):
            nonlocal fired
            if frame.f_code is audit.write_outputs.__code__ and event == 'line' and frame.f_locals.get('index') == 1 and not fired:
                fired = True
                raise KeyboardInterrupt
            return trace
        sys.settrace(trace)
        try:
            self.assertEqual(self.run_audit(lambda *_: reply({'success': True, 'sources': [{'name': 'New breach'}]})), 130)
        finally:
            sys.settrace(None)
        self.assertTrue(fired)
        self.assertEqual(self.rows()[0]['email'], 'new@example.com')
        self.assertIn('new@example.com', self.html())
        self.assertEqual(self.rows('findings.csv')[0]['email'], 'new@example.com')
        self.assertEqual(self.rows('findings.csv')[0]['breach'], 'New breach')
        self.assertFalse(list(self.out.glob('.*-*')))

    def test_directory_warning_only_for_read_permissions(self):
        self.out.mkdir()
        for mode in (0o700, 0o711, 0o722, 0o740, 0o704):
            with self.subTest(mode=oct(mode)):
                self.out.chmod(mode)
                self.assertEqual(self.run_audit(), 0)
                self.assertEqual('警告' in self.stderr, bool(mode & 0o044))
                self.assertEqual(self.out.stat().st_mode & 0o777, mode)

    def test_integer_option_upper_bounds(self):
        for option, maximum in (('--max-age', 36500), ('--recent-years', 100)):
            with self.subTest(option=option):
                self.assertEqual(self.run_audit(options=[option, str(maximum + 1)]), 2)
                self.assertEqual(self.calls, [])
                self.assertFalse(self.out.exists())
                self.assertEqual(self.run_audit(options=[option, str(maximum)]), 0)
                # Use another output directory for the next option.
                self.out = self.root / (option[2:] + '-output')
                self.calls.clear()

    def test_corrupt_cache_rows_ignored_and_requeried(self):
        mutations = [dict(status='wrong'), dict(fetched_at='bad'), dict(fetched_at='2026-10-10T00:00:00+00:00'),
                     dict(data='not json'), dict(data='{}'), dict(data='null'), dict(schema_version='bad'),
                     dict(status='error', data='{"kind":"wrong","reason":"x"}'),
                     dict(status='error', data='{"kind":"invalid","reason":5}')]
        good = record([source()])
        for field, value in [('found', 1), ('sources', {}), ('extra', {} )]:
            bad = dict(good, **{field: value})
            mutations.append(dict(data=json.dumps(bad)))
        for field, value in [('name', 1), ('breach_date', '2023-02-30'), ('has_password', 'maybe'),
                             ('flags', ['wrong']), ('catalog_miss', 1), ('data', [1]), ('added_date', 'bad')]:
            mutations.append(dict(data=json.dumps(record([dict(source(), **{field: value})]))))
        addresses = [f'bad{i}@example.com' for i in range(len(mutations))]
        self.input.write_text('\n'.join(addresses + ['good@example.com']))
        self.seed([('leakcheck', email, 'ok', record(), '2026-10-10T03:15:00Z', 2) for email in addresses + ['good@example.com']])
        with contextlib.closing(sqlite3.connect(self.out / 'cache.sqlite')) as db:
            for email, mutation in zip(addresses, mutations):
                for field, value in mutation.items():
                    db.execute(f'UPDATE results SET {field}=? WHERE email=?', (value, email))
            db.commit()
        self.assertEqual(self.run_audit(options=['--report-only']), 3)
        self.assertEqual([r['providers_not_queried'] for r in self.rows()], ['leakcheck'] * len(addresses) + [''])
        self.assertEqual(self.calls, [])
        self.assertEqual(self.run_audit(), 0)
        self.assertEqual(len(self.calls), len(addresses))

    def test_hibp_key_only_on_queries_including_refetch(self):
        def http(url, headers, _):
            if url.endswith('/breaches'):
                self.assertNotIn('hibp-api-key', headers)
                return reply([])
            self.assertEqual(headers['hibp-api-key'], 'test-key')
            return reply([{'Name': 'Missing'}])
        self.assertEqual(self.run_audit(http, providers='hibp', env={'HIBP_API_KEY': 'test-key'}), 0)
        self.assertEqual(sum(url.endswith('/breaches') for url in self.calls), 2)

    def test_no_catalog_refetch_after_stop(self):
        stop = threading.Event()
        def http(url, *_):
            if url.endswith('/breaches'):
                return reply([])
            stop.set()
            return reply([{'Name': 'Missing'}])
        real_event = threading.Event
        events = iter([stop])
        with patch.object(audit.threading, 'Event', side_effect=lambda: next(events, None) or real_event()):
            self.assertEqual(self.run_audit(http, providers='hibp', env={'HIBP_API_KEY': 'test-key'}), 130)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.rows('findings.csv')[0]['catalog_miss'], 'true')

    def test_html_section_order_and_search_before_table(self):
        self.assertEqual(self.run_audit(), 0)
        markup = self.html()
        markers = ['<h1>', '<h2>結果の要約', '照会できなかった照会先があるアドレス:',
                   '<h2>照会先ごとの状況', 'id="search"', '<h2>アドレスごとの結果',
                   '<h2>検出なしのアドレス', '<tr class="addr"', '<h2>区分の決め方と注意',
                   '検出は侵害を意味しない', '個人情報を含む', 'Powered by LeakCheck']
        positions = [markup.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))

    def test_a17_visible_japanese_report_all_values(self):
        addresses = [f'case{i}@example.com' for i in range(8)]
        self.input.write_text('\n'.join(addresses))
        all_data = list(audit.DATA_LABELS) + ['Unmapped information']
        items = [source(password=True, flags=list(audit.FLAGS)),
                 source(password=True), source(date='2000', precision='year', password=True),
                 source(password=False), None, 'error', source(), source()]
        # Critical needs a non-fabricated stealer source; the fabricated source
        # remains visible with every other caution.
        seeds = []
        for i, item in enumerate(items):
            if i == 5:
                seeds.append(('leakcheck', addresses[i], 'error', {'kind':'invalid','reason':'HTTP 400'}, '2026-10-10T03:15:00Z', 2))
                continue
            if i == 7:
                continue
            sources = [] if item is None else [dict(item, data=all_data, catalog_miss=True)]
            if i == 1:
                sources.append(source(name='Unknown password', date='2025-01-01', precision='day'))
            if i == 0:
                sources.append(source(name='Stealer', password=False, flags=['stealer_log']))
            seeds.append(('leakcheck', addresses[i], 'ok', record(sources, {'fields':['password'] if i == 6 else [], 'password_field':i == 6}), '2026-10-10T03:15:00Z', 2))
        self.seed(seeds)
        self.assertEqual(self.run_audit(options=['--report-only'], providers='hibp,leakcheck'), 3)
        markup = self.html()
        class TextParser(HTMLParser):
            def __init__(self):
                super().__init__(); self.hidden = 0; self.text = []; self.tags = []
            def handle_starttag(self, tag, attrs):
                self.tags.append(tag)
                if tag in ('script','style'): self.hidden += 1
            def handle_endtag(self, tag):
                if tag in ('script','style'): self.hidden -= 1
            def handle_data(self, data):
                if not self.hidden: self.text.append(data)
        parser = TextParser(); parser.feed(markup)
        visible = ' '.join(parser.text)
        self.assertNotIn('details', parser.tags)
        import re
        forbidden = set(audit.SUMMARY + audit.FINDINGS + list(audit.RISKS) + list(audit.FLAGS) +
                        ['ok','error','not_queried','skipped','complete','partial','true','false','maybe',
                         'corporate_services','user_services','report-only'])
        for word in forbidden:
            self.assertIsNone(re.search(r'(?<![A-Za-z0-9_])'+re.escape(word)+r'(?![A-Za-z0-9_])', visible), word)
        for label in list(audit.RISKS.values()) + ['照会済み','エラー','未照会','照会しなかった',
                '含む','含まない','含む可能性あり','不明（含むとして扱う）',
                '情報窃取マルウェア由来','スパム用リスト','作られたデータの疑い（判定に使わない）',
                '未検証','マルウェア関連','照会先の一覧に詳細なし',
                '日付不明（直近として扱う）','はい','いいえ', 'Unmapped information'] + list(audit.DATA_LABELS.values()):
            self.assertIn(label, visible)
        self.assertEqual(markup.count('<section class="addr"'), 7)
        self.assertEqual(markup.count('<tr class="addr"'), 1)
        self.assertIn('@page{size:A4 portrait', markup)
        self.assertIn('@media(prefers-color-scheme:dark)', markup)

    def test_a18_run_records_immutable_and_complete(self):
        self.input.write_text('one@example.com\ntwo@example.org')
        self.assertEqual(self.run_audit(providers='hibp,leakcheck'), 0)
        runs = self.out / 'runs'
        first = next(runs.iterdir())
        snapshot = {p.name:p.read_bytes() for p in first.iterdir()}
        self.assertEqual(set(snapshot), {'summary.csv','findings.csv','report.html','results.jsonl','run.json'})
        metadata = json.loads(snapshot['run.json'])
        self.assertEqual(list(metadata), ['tool_version','started_at','finished_at','mode','input_file','addresses','options','effective_providers','skipped_providers','provider_notes','risk_counts','partial','exit_code'])
        self.assertEqual(metadata, dict(tool_version=audit.__version__, started_at='2026-10-10T03:15:00Z',
            finished_at='2026-10-10T03:15:00Z', mode='normal', input_file='input.txt', addresses=2,
            options=dict(providers=['hibp','leakcheck'],max_age=7,refresh=False,recent_years=3,limit=None),
            effective_providers=['leakcheck'],skipped_providers={'hibp':'HIBP_API_KEY が未設定'},
            provider_notes={'hibp':'スキップ: HIBP_API_KEY が未設定'},
            risk_counts={r:2 if r=='none' else 0 for r in audit.RISKS},partial=0,exit_code=0))
        lines = [json.loads(line) for line in snapshot['results.jsonl'].splitlines()]
        self.assertEqual(len(lines), 4)
        for index, value in enumerate(lines):
            provider = ['hibp','leakcheck'][index % 2]
            self.assertEqual(list(value), ['email','provider','state','fetched_at','queried_now','result','error'])
            self.assertEqual(value, dict(email=['one@example.com','two@example.org'][index//2],provider=provider,
                state='skipped' if provider=='hibp' else 'ok', fetched_at=None if provider=='hibp' else '2026-10-10T03:15:00Z',
                queried_now=provider=='leakcheck',result=None if provider=='hibp' else record(),error=None))
        for name in ('summary.csv','findings.csv','report.html'):
            self.assertEqual(snapshot[name], (self.out/name).read_bytes())
        self.assertEqual(self.run_audit(options=['--report-only'],providers='hibp,leakcheck'), 0)
        self.assertEqual(len(list(runs.iterdir())), 2)
        second = runs / (first.name+'-2')
        self.assertTrue(second.is_dir())
        self.assertEqual(snapshot, {p.name:p.read_bytes() for p in first.iterdir()})
        self.assertEqual(json.loads((second/'run.json').read_text())['mode'], 'report_only')
        self.assertTrue(all(not json.loads(line)['queried_now'] for line in (second/'results.jsonl').read_text().splitlines()))
        self.assertIn(str(second), self.stderr)
        for path in [runs, *runs.rglob('*')]:
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)

    def test_run_record_errors_missing_and_retained_success(self):
        self.input.write_text('old@example.com\nerror@example.com\nmissing@example.com')
        old = record([source(password=False)])
        self.seed([('leakcheck','old@example.com','ok',old,'2020-01-01T00:00:00Z',2)])
        def http(url, *_):
            if 'old%40' in url: return reply({}, 503)
            if 'error%40' in url: return reply({}, 400)
            raise KeyboardInterrupt
        self.assertEqual(self.run_audit(http), 130)
        run = next((self.out/'runs').iterdir())
        lines = [json.loads(line) for line in (run/'results.jsonl').read_text().splitlines()]
        self.assertEqual(lines, [
            dict(email='old@example.com',provider='leakcheck',state='ok',fetched_at='2020-01-01T00:00:00Z',queried_now=True,result=old,error=None),
            dict(email='error@example.com',provider='leakcheck',state='error',fetched_at='2026-10-10T03:15:00Z',queried_now=True,result=None,error={'kind':'invalid','reason':'HTTP 400'}),
            dict(email='missing@example.com',provider='leakcheck',state='not_queried',fetched_at=None,queried_now=False,result=None,error=None)])
        metadata = json.loads((run/'run.json').read_text())
        self.assertEqual(metadata['exit_code'],130)
        self.assertEqual(metadata['partial'],2)
        self.assertEqual(metadata['provider_notes'], {'leakcheck':'中断（3 件中 2 件を完了）'})
        self.assertIn('古い結果',self.html())

    def test_html_infection_table_and_critical_reasons(self):
        self.input.write_text('both@example.com\ninfection@example.com')
        infected = {'infections':2,'compromised_dates':['2025-01-02'],'corporate_services':3,'user_services':4}
        self.seed([('hudsonrock',email,'ok',record(extra=infected),'2026-10-10T03:15:00Z',2)
                   for email in ('both@example.com','infection@example.com')] +
                  [('leakcheck','both@example.com','ok',record([source(flags=['stealer_log'])]),'2026-10-10T03:15:00Z',2),
                   ('leakcheck','infection@example.com','ok',record(),'2026-10-10T03:15:00Z',2)])
        self.assertEqual(self.run_audit(options=['--report-only'],providers='leakcheck,hudsonrock'),0)
        markup=self.html()
        self.assertIn('インフォスティーラーの感染記録が 2 件ある。情報窃取マルウェア由来の流出元が 1 件ある',markup)
        self.assertEqual(markup.count('感染の記録の件数'),2)
        self.assertEqual(markup.count('感染した端末にあった社内サービスの認証情報の数'),2)
        self.assertIn('個人向けサービスの認証情報の数',markup)
        self.assertIn('2025-01-02',markup)
        self.assertNotIn('corporate_services',markup)
        self.assertNotIn('user_services',markup)

    def test_interrupt_after_record_rename_completes_outputs(self):
        self.assertEqual(self.run_audit(), 0)
        self.input.write_text('new@example.com')
        real_rename = audit.os.rename
        fired = False
        def rename(src, dst):
            nonlocal fired
            real_rename(src, dst)
            fired = True
            raise KeyboardInterrupt
        with patch.object(audit.os, 'rename', side_effect=rename):
            self.assertEqual(self.run_audit(lambda *_: reply({'success':True,'sources':[{'name':'New breach'}]})), 130)
        self.assertTrue(fired)
        latest = sorted((self.out/'runs').iterdir())[-1]
        self.assertEqual(json.loads((latest/'run.json').read_text())['exit_code'], 130)
        for name in ('summary.csv','findings.csv','report.html'):
            self.assertEqual((latest/name).read_bytes(), (self.out/name).read_bytes())
        self.assertEqual(self.rows()[0]['email'], 'new@example.com')
        self.assertFalse(list(self.out.rglob('.tmp-*')))

    def test_interrupt_before_record_rename_keeps_previous_outputs(self):
        self.assertEqual(self.run_audit(), 0)
        snapshot = {name:(self.out/name).read_bytes() for name in ('summary.csv','findings.csv','report.html')}
        self.input.write_text('new@example.com')
        real_json = audit.json_text
        def interrupt(value):
            if isinstance(value, dict) and 'finished_at' in value:
                raise KeyboardInterrupt
            return real_json(value)
        with patch.object(audit, 'json_text', side_effect=interrupt):
            self.assertEqual(self.run_audit(), 130)
        self.assertEqual(snapshot, {name:(self.out/name).read_bytes() for name in snapshot})
        self.assertEqual(len(list((self.out/'runs').iterdir())), 1)
        self.assertFalse(list(self.out.rglob('.tmp-*')))
        self.assertFalse(list(self.out.glob('.*-*')))

    def test_a06_remaining_rate_limit_rules(self):
        cases = [
            ([reply({}, 429, {'retry-after': '601'})], []),
            ([reply({}, 429, {'retry-after': '+5'})] * 3, [30, 60]),
            ([reply({}, 429)] * 2 + [reply({}, 503)] + [reply({}, 429)] * 3, [30, 60, 15, 120, 150]),
            ([reply({}, 429)] * 2 + [reply({}, 429, {'retry-after': '5'})] + [reply({}, 429)] * 3, [30, 60, 6, 120, 150]),
            ([reply({}, 503)] * 7 + [reply({}, 429, {'retry-after': '5'})], [5, 10, 15, 20, 25, 30, 35]),
        ]
        for responses, waits in cases:
            with self.subTest(waits=waits):
                self.calls.clear()
                self.waits.clear()
                replies = iter(responses)
                self.assertEqual(self.run_audit(lambda *_: next(replies)), 3)
                self.assertEqual(self.waits, waits)
                self.assertEqual(len(self.calls), len(responses))
                self.assertEqual(self.rows()[0]['providers_not_queried'], 'leakcheck')
                self.assertIn('停止: 1 / 1 件目で上限に達した。時間をおいて再実行すると続きから進みます', self.html())
                with contextlib.closing(sqlite3.connect(self.out / 'cache.sqlite')) as db:
                    self.assertEqual(db.execute('SELECT count(*) FROM results').fetchone()[0], 0)

if __name__ == '__main__':
    unittest.main()
