"""Tests for start-here.py: the pure helpers, the HTTP guard, and a full USB provisioning
run against a fake board on a pseudo-terminal (POSIX only, needs pyserial).

    python3 -m unittest discover -s tools -p 'test_*.py' -v
"""
import hashlib
import importlib.util
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('start_here', os.path.join(HERE, '..', 'start-here.py'))
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)

try:
    import serial  # noqa: F401
    HAVE_SERIAL = True
except ImportError:
    HAVE_SERIAL = False


class PureHelpers(unittest.TestCase):
    def test_provision_line_hex_and_empty(self):
        line = sh.provision_line('My "Net"', '', 'adminpass1')
        self.assertEqual(line, 'PROVISION %s - %s\n' % (b'My "Net"'.hex(), b'adminpass1'.hex()))
        self.assertTrue(sh.provision_line('n', 'wifipass', 'adminpass', 'oldadmin1').rstrip().endswith(b'oldadmin1'.hex()))

    def test_provision_line_unicode_and_spaces(self):
        line = sh.provision_line('Café Wi Fi', 'pä ss wörd', 'a d m i n ü')
        self.assertEqual(len(line.split()), 4)                 # spaces never split a field
        self.assertEqual(bytes.fromhex(line.split()[1]).decode(), 'Café Wi Fi')

    def test_provision_line_rejects(self):
        for args in (('', 'wifipass', 'adminpass'), ('x' * 33, '', 'adminpass'), ('net', 'short', 'adminpass'),
                     ('net', 'x' * 64, 'adminpass'), ('net', '', 'short'), ('net', 'wifi\0pass', 'adminpass')):
            with self.assertRaises(ValueError, msg=args):
                sh.provision_line(*args)

    def test_parse_info(self):
        i = sh.parse_info('[info] mode=online ip=192.168.1.50 ap="C3-AdBlock-1A2B" fp=AB:CD admin=set')
        self.assertEqual(i, {'mode': 'online', 'ip': '192.168.1.50', 'ap': 'C3-AdBlock-1A2B', 'fp': 'AB:CD', 'admin': True})
        self.assertEqual(sh.parse_info('[info] mode=setup ip= ap="C3-AdBlock-1A2B" fp= admin=unset')['mode'], 'setup')
        self.assertIsNone(sh.parse_info('[setup] something else'))
        i = sh.parse_info('[info] mode=online ip=10.0.0.2 ap="C3-AdBlock-1A2B" fp=AB admin=set heap=81234 maxblock=40000')
        self.assertEqual((i['heap'], i['maxblock']), (81234, 40000))

    def test_parse_nets(self):
        line = '[nets] ' + ','.join(n.encode().hex() for n in ('Home', 'Café', 'Home', ''))
        self.assertEqual(sh.parse_nets(line), ['Home', 'Café'])
        self.assertIsNone(sh.parse_nets('[nets] error not in setup mode'))
        self.assertEqual(sh.parse_nets('[nets] '), [])

    def test_sha256_ok(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'adblock-c3.bin')
            open(p, 'wb').write(b'firmware')
            good = hashlib.sha256(b'firmware').hexdigest()
            self.assertTrue(sh.sha256_ok(p, '%s  adblock-c3.bin\n%s  adblock-s3.bin\n' % (good, '0' * 64), 'adblock-c3.bin'))
            self.assertFalse(sh.sha256_ok(p, '%s  adblock-c3.bin\n' % ('0' * 64), 'adblock-c3.bin'))
            self.assertFalse(sh.sha256_ok(p, '%s  other.bin\n' % good, 'adblock-c3.bin'))

    def test_host_ok(self):
        self.assertTrue(sh.host_ok('127.0.0.1:8765', 8765))
        self.assertTrue(sh.host_ok('localhost:8765', 8765))
        for h in ('evil.example:8765', '127.0.0.1:8766', '127.0.0.1', ''):
            self.assertFalse(sh.host_ok(h, 8765))

    def test_chip_from_esptool(self):
        self.assertEqual(sh.chip_from_esptool('Detecting chip type... ESP32-C3\nChip type: ESP32-C3 (QFN32) (revision v0.4)'), 'c3')
        self.assertEqual(sh.chip_from_esptool('Chip type: ESP32-S3 (QFN56) (revision v0.2)'), 's3')
        self.assertEqual(sh.chip_from_esptool('Chip type: ESP32-D0WD-V3 (revision v3.1)'), 'esp32')
        self.assertEqual(sh.chip_from_esptool('Chip is ESP32-PICO-D4 (revision 1)'), 'esp32')
        self.assertIsNone(sh.chip_from_esptool('Chip type: ESP32-C6 (QFN40)'))
        self.assertIsNone(sh.chip_from_esptool('A fatal error occurred: Failed to connect'))


class JobLogAndHints(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self._cache = sh.CACHE
        sh.CACHE = d.name
        self.addCleanup(setattr, sh, 'CACHE', self._cache)

    def test_full_log_incremental_and_file(self):
        job = sh.Job('install')
        for i in range(1000):
            job.say('line %d' % i)
        v = job.view()
        self.assertEqual(len(v['log']), 1000)                 # the whole log, not a tail
        self.assertEqual(v['logTotal'], 1000)
        v2 = job.view(990)
        self.assertEqual(v2['log'][0], 'line 990')
        self.assertEqual(v2['logFrom'], 990)
        job.close()
        self.assertEqual(open(v['logFile']).read().count('\n'), 1000)

    def test_trimmed_log_keeps_absolute_positions(self):
        old = sh.LOG_MAX
        sh.LOG_MAX = 10
        self.addCleanup(setattr, sh, 'LOG_MAX', old)
        job = sh.Job('x')
        for i in range(25):
            job.say(str(i))
        v = job.view(3)                                        # asked for lines already trimmed
        self.assertEqual(v['logFrom'], 15)
        self.assertEqual(v['log'][0], '15')
        self.assertEqual(job.view(24)['log'], ['24'])
        job.close()

    def test_explain_failure(self):
        self.assertIn('Rosetta', sh.explain_failure(['sh: line 1: /x/mklittlefs: Bad CPU type in executable']))
        self.assertIn('in use', sh.explain_failure(["could not open port /dev/cu.usbmodem1: [Errno 16] Resource busy"]))
        self.assertEqual(sh.explain_failure(['all good']), '')

    def test_failed_job_reports_likely_cause(self):
        helper = sh.Helper()

        def boom(job):
            job.say('sh: line 1: /Users/x/.platformio/packages/tool-mklittlefs/mklittlefs: Bad CPU type in executable')
            raise RuntimeError('flashing the blocklist failed (see the log)')
        helper.start_job('install', boom)
        for _ in range(100):
            if helper.job.state != 'running':
                break
            threading.Event().wait(0.02)
        v = helper.job.view()
        self.assertEqual(v['state'], 'error')
        self.assertIn('Rosetta', v['error'])
        self.assertIn('softwareupdate --install-rosetta', v['error'])

    def test_needs_rosetta_only_on_apple_silicon(self):
        import unittest.mock as m
        with m.patch.object(sh.sys, 'platform', 'linux'):
            self.assertFalse(sh.needs_rosetta())
        with m.patch.object(sh.sys, 'platform', 'darwin'), m.patch.object(sh.platform, 'machine', return_value='x86_64'):
            self.assertFalse(sh.needs_rosetta())
        with m.patch.object(sh.sys, 'platform', 'darwin'), m.patch.object(sh.platform, 'machine', return_value='arm64'):
            with m.patch.object(sh.subprocess, 'call', return_value=1):
                self.assertTrue(sh.needs_rosetta())
            with m.patch.object(sh.subprocess, 'call', return_value=0):
                self.assertFalse(sh.needs_rosetta())


class ConsoleCommands(unittest.TestCase):
    def test_allowed(self):
        self.assertEqual(sh.console_command(' INFO '), 'INFO\n')
        self.assertEqual(sh.console_command('DIAG  on'), 'DIAG on\n')
        self.assertEqual(sh.console_command('NETS'), 'NETS\n')

    def test_refused(self):
        for bad in ('PROVISION 41 - 61', 'info', 'DIAG maybe', 'INFO\nPROVISION 41 - 61', ''):
            with self.assertRaises(ValueError, msg=bad):
                sh.console_command(bad)


class HttpGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from http.server import ThreadingHTTPServer
        cls.helper = sh.Helper()
        cls.srv = ThreadingHTTPServer(('127.0.0.1', 0), None)
        cls.port = cls.srv.server_address[1]
        cls.srv.RequestHandlerClass = sh.make_handler(cls.helper, cls.port)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def req(self, path, host=None, token=None, data=None):
        r = urllib.request.Request('http://127.0.0.1:%d%s' % (self.port, path), data=data)
        if host:
            r.add_header('Host', host)
        if token:
            r.add_header('X-Setup-Token', token)
        try:
            with urllib.request.urlopen(r, timeout=5) as resp:
                return resp.status, resp.read().decode(), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), dict(e.headers)

    def test_page_carries_token(self):
        code, body, _ = self.req('/')
        self.assertEqual(code, 200)
        self.assertIn(self.helper.token, body)
        self.assertNotIn('<!--HELPER-->', body)

    def test_rebinding_host_refused(self):
        self.assertEqual(self.req('/', host='attacker.example:%d' % self.port)[0], 403)

    def test_api_needs_token(self):
        self.assertEqual(self.req('/api/job')[0], 403)
        self.assertEqual(self.req('/api/job', token='wrong')[0], 403)
        self.assertEqual(self.req('/api/job', token=self.helper.token)[0], 200)
        self.assertEqual(self.req('/api/provision', data=b'{}')[0], 403)

    def test_job_since(self):
        job = self.helper.job = sh.Job('t')
        self.addCleanup(job.close)
        for i in range(5):
            job.say('l%d' % i)
        code, body, _ = self.req('/api/job?since=3', token=self.helper.token)
        self.assertEqual(json.loads(body)['log'], ['l3', 'l4'])
        self.helper.job = None

    def test_api_has_no_cors(self):
        _, _, h = self.req('/api/job', token=self.helper.token)
        self.assertNotIn('Access-Control-Allow-Origin', h)

    def test_ping_is_open_but_empty(self):
        code, body, h = self.req('/ping')
        self.assertEqual(code, 200)
        self.assertEqual(h.get('Access-Control-Allow-Origin'), '*')
        self.assertNotIn(self.helper.token, body)

    def test_bad_provision_rejected_before_job(self):
        code, body, _ = self.req('/api/provision', token=self.helper.token,
                                 data=json.dumps({'port': 'x', 'ssid': 'net', 'pass': '', 'admin': 'short'}).encode())
        self.assertEqual(code, 400)
        self.assertIn('admin password', body)
        self.assertIsNone(self.helper.job)


class FakeBoard(threading.Thread):
    """Answers INFO / NETS / PROVISION on a pty the way the firmware does."""

    def __init__(self, master, wifi_ok=True):
        super().__init__(daemon=True)
        self.master, self.wifi_ok, self.online, self.ip, self.seen = master, wifi_ok, False, '', []

    def out(self, s):
        os.write(self.master, (s + '\r\n').encode())

    def run(self):
        buf = b''
        while True:
            try:
                data = os.read(self.master, 1024)
            except OSError:
                return
            buf += data
            while b'\n' in buf:
                raw, buf = buf.split(b'\n', 1)
                line = raw.decode().strip()
                self.seen.append(line.split(' ')[0])
                if line == 'INFO':
                    self.out('[info] mode=%s ip=%s ap="C3-AdBlock-1A2B" fp=AA:BB:CC admin=%s'
                             % ('online' if self.online else 'setup', self.ip, 'set' if self.online else 'unset'))
                elif line == 'NETS':
                    self.out('[nets] ' + ','.join(n.encode().hex() for n in ('Home', 'Neighbour')))
                elif line.startswith('PROVISION '):
                    f = line.split()[1:]
                    self.provisioned = [bytes.fromhex(x).decode() if x != '-' else '' for x in f]
                    self.out('[provision] ok, restarting to join "%s"' % self.provisioned[0])
                    self.out('[c3-adblock] booting')
                    if self.wifi_ok:
                        self.online, self.ip = True, '192.168.1.77'
                        self.out('WiFi up: 192.168.1.77')
                    else:
                        self.out('')
                        self.out('[setup] No WiFi. Join "C3-AdBlock-1A2B" (password x) and a setup page pops up')


@unittest.skipUnless(HAVE_SERIAL and os.name == 'posix', 'needs pyserial and a POSIX pty')
class Provisioning(unittest.TestCase):
    def board(self, wifi_ok=True):
        import pty
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        fake = FakeBoard(master, wifi_ok)
        fake.start()
        helper = sh.Helper()
        self.addCleanup(helper.stop_monitor)
        return helper, fake, os.ttyname(slave)

    def wait(self, helper):
        for _ in range(400):
            v = helper.job.view()
            if v['state'] != 'running':
                return v
            threading.Event().wait(0.05)
        self.fail('job did not finish')

    def test_info_and_nets(self):
        helper, _, port = self.board()
        helper.start_job('info', helper.info, port)
        v = self.wait(helper)
        self.assertEqual(v['state'], 'ok', v)
        self.assertEqual(v['result']['mode'], 'setup')
        self.assertEqual(helper.nets(port), ['Home', 'Neighbour'])

    def test_provision_success(self):
        helper, fake, port = self.board()
        helper.start_job('provision', helper.provision, port, 'Home', 'wifipass1', 'adminpass1', '')
        v = self.wait(helper)
        self.assertEqual(v['state'], 'ok', v)
        self.assertEqual(v['result']['ip'], '192.168.1.77')
        self.assertEqual(v['result']['fp'], 'AA:BB:CC')
        self.assertEqual(fake.provisioned, ['Home', 'wifipass1', 'adminpass1'])
        self.assertFalse(any('wifipass1' in l or 'adminpass1' in l for l in v['log']))   # never logged

    def test_provision_wrong_wifi_password(self):
        helper, _, port = self.board(wifi_ok=False)
        helper.start_job('provision', helper.provision, port, 'Home', 'wrongpass', 'adminpass1', '')
        v = self.wait(helper)
        self.assertEqual(v['state'], 'error')
        self.assertIn("couldn't join", v['error'])


class NoAnswerReasons(unittest.TestCase):
    def test_port_busy(self):
        r = sh.no_answer_reason('/dev/x', False, '[Errno 16] could not open port /dev/x: Resource busy', [], 25)
        self.assertIn('Another program is using the board', r)

    def test_silent(self):
        self.assertIn('sent nothing', sh.no_answer_reason('/dev/x', True, '', [], 25))

    def test_old_firmware(self):
        r = sh.no_answer_reason('/dev/x', True, '', ['[c3-adblock] booting', 'blocklist: 104381 domains'], 25)
        self.assertIn('older version', r)

    def test_crash_loop(self):
        seen = ['rst:0xc (SW_CPU_RESET),boot:0x13', 'Guru Meditation Error: Core 0 panic', 'Backtrace: 0x4008',
                'rst:0xc (SW_CPU_RESET),boot:0x13']
        self.assertIn('keeps crashing', sh.no_answer_reason('/dev/x', True, '', seen, 25))
        # A normal power-on reset line alone is not a crash.
        self.assertIn('older version', sh.no_answer_reason('/dev/x', True, '', ['rst:0x1 (POWERON_RESET),boot:0x13'], 25))


class Chatter(threading.Thread):
    """A board that prints lines but never answers INFO (older firmware)."""

    def __init__(self, master, lines):
        super().__init__(daemon=True)
        self.master, self.lines = master, lines

    def run(self):
        for l in self.lines:
            try:
                os.write(self.master, (l + '\r\n').encode())
            except OSError:
                return
            threading.Event().wait(0.1)


@unittest.skipUnless(HAVE_SERIAL and os.name == 'posix', 'needs pyserial and a POSIX pty')
class NoAnswerOnPty(unittest.TestCase):
    def setUp(self):
        import pty
        self.master, slave = pty.openpty()
        self.addCleanup(os.close, self.master)
        self.addCleanup(os.close, slave)
        self.port = os.ttyname(slave)
        self.helper = sh.Helper()
        self.addCleanup(self.helper.stop_monitor)
        self._cache = sh.CACHE
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        sh.CACHE = d.name
        self.addCleanup(setattr, sh, 'CACHE', self._cache)

    def test_old_firmware_console_lands_in_log(self):
        Chatter(self.master, ['[c3-adblock] booting', 'blocklist: 104381 domains', 'WiFi up: 192.168.1.9']).start()
        job = sh.Job('info')
        with self.assertRaises(RuntimeError) as e:
            self.helper.read_info(job, self.port, 4)
        self.assertIn('older version', str(e.exception))
        self.assertIn('  blocklist: 104381 domains', job.log)       # Details shows what the board printed
        job.close()

    def test_silent_board(self):
        job = sh.Job('info')
        with self.assertRaises(RuntimeError) as e:
            self.helper.read_info(job, self.port, 3)
        self.assertIn('sent nothing', str(e.exception))
        job.close()


if __name__ == '__main__':
    unittest.main()
