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


if __name__ == '__main__':
    unittest.main()
