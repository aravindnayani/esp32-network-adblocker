#!/usr/bin/env python3
"""Setup helper for C3 AdBlock.

    python3 start-here.py        (Windows: py start-here.py)

Opens START-HERE.html in your browser and does the work behind it: checks what's
installed, finds the board on USB, flashes it, and sends your WiFi and admin password
to it over the USB cable. Works the same in Chrome, Edge, Safari and Firefox.

The first run creates .setup-venv/ in this folder and installs esptool (Espressif's
flasher) and certifi (root certificates) into it. Nothing is installed system-wide;
delete .setup-venv/ and .setup-cache/ to remove everything. Building from source also
installs PlatformIO there.

Security: the server listens on 127.0.0.1 only, answers only requests addressed to
127.0.0.1/localhost (no DNS rebinding), and every API call must carry a random token
that is only in the page it serves. Passwords pass straight to the board and are never
written to disk or logged.
"""
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
VENV = os.path.join(HERE, '.setup-venv')
CACHE = os.path.join(HERE, '.setup-cache')
PAGE = os.path.join(HERE, 'START-HERE.html')
SITE = 'https://aravindnayani.github.io/esp32-network-adblocker/'
ESPTOOL_REQ = 'esptool==5.5.0'
PORTS = range(8765, 8776)              # START-HERE.html probes these from file://
CHIPS = {'c3': 'esp32c3', 's3': 'esp32s3', 'esp32': 'esp32'}
ENVS = {'c3': 'c3', 's3': 's3', 'esp32': 'esp32dev'}
# USB vendor IDs of the serial chips ESP32 boards use. 303a = Espressif's built-in USB (C3, S3).
VIDS = {0x303a: 'built-in USB (ESP32-C3/S3)', 0x10c4: 'CP210x USB-serial', 0x1a86: 'CH340 USB-serial',
        0x0403: 'FTDI USB-serial'}


def venv_python():
    return os.path.join(VENV, 'Scripts' if os.name == 'nt' else 'bin', 'python.exe' if os.name == 'nt' else 'python')


def in_venv():
    return os.path.abspath(sys.prefix) == os.path.abspath(VENV)


def bootstrap():
    """Create .setup-venv with esptool + certifi and re-run this script inside it."""
    if sys.version_info < (3, 9):
        sys.exit('Python 3.9 or newer is needed (this is %s). See START-HERE.html, step 1.' % platform.python_version())
    if in_venv():
        return
    py = venv_python()
    if not os.path.exists(py):
        print('First run: setting up .setup-venv/ (esptool, certifi) in this folder. This takes about a minute.')
        try:
            subprocess.check_call([sys.executable, '-m', 'venv', VENV])
        except Exception as e:
            hint = '  On Debian/Ubuntu: sudo apt install python3-venv' if sys.platform.startswith('linux') else ''
            sys.exit('Could not create .setup-venv: %s\n%s' % (e, hint))
    probe = subprocess.call([py, '-c', 'import esptool, certifi, serial'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if probe != 0:
        print('Installing %s and certifi into .setup-venv ...' % ESPTOOL_REQ)
        subprocess.check_call([py, '-m', 'pip', 'install', '--disable-pip-version-check', ESPTOOL_REQ, 'certifi'])
    try:
        sys.exit(subprocess.call([py, os.path.abspath(__file__)] + sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(0)


# ---------------------------------------------------------------- pure helpers (tested)

def hexs(s):
    """A PROVISION field: UTF-8 as hex, '-' for empty."""
    return s.encode('utf-8').hex() if s else '-'


def provision_line(ssid, wifi_pass, admin, current=''):
    for name, v, lo, hi in (('WiFi name', ssid, 1, 32), ('admin password', admin, 8, 128)):
        n = len(v.encode('utf-8'))
        if not lo <= n <= hi:
            raise ValueError('%s must be %d to %d bytes' % (name, lo, hi))
    if wifi_pass and not 8 <= len(wifi_pass.encode('utf-8')) <= 63:
        raise ValueError('WiFi password must be 8 to 63 characters (or empty for an open network)')
    for v in (ssid, wifi_pass, admin, current):
        if '\0' in v:
            raise ValueError('passwords and names cannot contain a NUL character')
    f = [hexs(ssid), hexs(wifi_pass), hexs(admin)] + ([hexs(current)] if current else [])
    return 'PROVISION ' + ' '.join(f) + '\n'


INFO_RE = re.compile(r'^\[info\] mode=(\w+) ip=(\S*) ap="([^"]*)" fp=(\S*) admin=(\w+)')
FP_RE = re.compile(r'\[https\] certificate SHA-256 fingerprint: (\S+)')
UP_RE = re.compile(r'^WiFi up: (\d+\.\d+\.\d+\.\d+)')


def parse_info(line):
    m = INFO_RE.match(line)
    if not m:
        return None
    info = {'mode': m.group(1), 'ip': m.group(2), 'ap': m.group(3), 'fp': m.group(4), 'admin': m.group(5) == 'set'}
    mem = re.search(r' heap=(\d+) maxblock=(\d+)', line)          # newer firmware also reports memory
    if mem:
        info['heap'], info['maxblock'] = int(mem.group(1)), int(mem.group(2))
    return info


CONSOLE_CMDS = re.compile(r'^(INFO|NETS|DIAG( on| off)?)$')


def console_command(text):
    """A command the page may send to the board as typed. PROVISION is not one of them:
    passwords only go through the WiFi form."""
    t = ' '.join(text.split())
    if not CONSOLE_CMDS.match(t):
        raise ValueError('only INFO, NETS, DIAG, DIAG on and DIAG off can be sent from here')
    return t + '\n'


def parse_nets(line):
    if not line.startswith('[nets] ') or line.startswith('[nets] error'):
        return None
    out = []
    for h in line[7:].strip().split(','):
        try:
            name = bytes.fromhex(h).decode('utf-8', 'replace')
        except ValueError:
            continue
        if name and name not in out:
            out.append(name)
    return out


def sha256_ok(path, sums_text, name):
    want = None
    for line in sums_text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip('*') == name:
            want = parts[0].lower()
    if not want:
        return False
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 16), b''):
            h.update(chunk)
    return h.hexdigest() == want


def host_ok(host, port):
    return host in ('127.0.0.1:%d' % port, 'localhost:%d' % port)


def chip_from_esptool(out):
    """'c3', 's3', 'esp32' (classic, any package such as ESP32-D0WD-V3), or None (unsupported)."""
    m = re.search(r'(?:Chip type|Chip is|Detecting chip type)[:.\s]*(ESP32[-\w]*)', out)
    if not m:
        return None
    name = m.group(1).upper()
    if name.startswith('ESP32-C3'):
        return 'c3'
    if name.startswith('ESP32-S3'):
        return 's3'
    if re.match(r'ESP32-(S2|C2|C5|C6|C61|H2|H4|P4)\b', name):
        return None
    return 'esp32'


# ---------------------------------------------------------------- serial monitor

class Monitor:
    """Keeps the board's USB console open, collects its lines, and reconnects across the
    resets that flashing and PROVISION cause (the USB port drops and comes back)."""

    def __init__(self, port):
        self.port, self.lines, self.cv = port, [], threading.Condition()
        self.ser, self.stop_flag = None, False
        self.open_error = ''                              # why the port last failed to open, if it did
        self.t = threading.Thread(target=self.run, daemon=True)
        self.t.start()

    def run(self):
        import serial
        buf = b''
        while not self.stop_flag:
            if self.ser is None:
                try:
                    s = serial.Serial()
                    s.port, s.baudrate, s.timeout = self.port, 115200, 0.2
                    s.write_timeout = 2              # a stuck board must not hang the helper
                    s.dtr = False                  # don't hold the chip in reset / download mode
                    s.rts = False
                    s.open()
                    self.ser, self.open_error = s, ''
                except Exception as e:
                    self.open_error = str(e) or e.__class__.__name__
                    time.sleep(0.5)
                    continue
            try:
                data = self.ser.read(512)
            except Exception:
                try:
                    self.ser.close()
                except Exception:
                    pass
                self.ser = None
                continue
            if not data:
                continue
            buf += data
            while b'\n' in buf:
                raw, buf = buf.split(b'\n', 1)
                line = raw.decode('utf-8', 'replace').rstrip('\r')
                with self.cv:
                    self.lines.append(line)
                    del self.lines[:-400]
                    self.cv.notify_all()

    def send(self, text):
        for _ in range(40):
            if self.ser is not None:
                try:
                    self.ser.write(text.encode('utf-8'))   # no flush(): tcdrain() can block forever
                    return True
                except Exception:
                    pass
            time.sleep(0.25)
        return False

    def mark(self):
        with self.cv:
            return len(self.lines)

    def wait_for(self, start, test, timeout):
        """First line from index start on for which test(line) returns a value, or None."""
        end = time.time() + timeout
        i = start
        with self.cv:
            while True:
                while i < len(self.lines):
                    r = test(self.lines[i])
                    i += 1
                    if r is not None:
                        return r
                left = end - time.time()
                if left <= 0:
                    return None
                self.cv.wait(min(left, 0.5))
                i = min(i, len(self.lines))

    def lines_since(self, start):
        with self.cv:
            return list(self.lines[start:])

    def tail(self, n=60):
        with self.cv:
            return list(self.lines[-n:])

    def close(self):
        self.stop_flag = True
        self.t.join(timeout=2)
        try:
            if self.ser:
                self.ser.close()
        except Exception:
            pass


# ---------------------------------------------------------------- jobs

LOG_MAX = 50000                         # lines kept in memory per step; the log file has everything


class Job:
    """One step's state and its full log, which also goes to .setup-cache/logs/ as it's written.
    The page fetches the log incrementally (view(since)), so long builds come through whole."""

    def __init__(self, kind):
        self.kind, self.state, self.step, self.log, self.result, self.error = kind, 'running', '', [], None, ''
        self.dropped = 0                                   # lines trimmed from the front of self.log
        self.lock = threading.Lock()
        self.logfile = None
        try:
            os.makedirs(os.path.join(CACHE, 'logs'), exist_ok=True)
            self.logfile = os.path.join(CACHE, 'logs', time.strftime('%Y%m%d-%H%M%S-') + kind + '.log')
            self.fh = open(self.logfile, 'w', encoding='utf-8')
        except OSError:
            self.logfile, self.fh = None, None

    def say(self, line):
        with self.lock:
            self.log.append(line)
            if len(self.log) > LOG_MAX:
                cut = len(self.log) - LOG_MAX
                del self.log[:cut]
                self.dropped += cut
            if self.fh:
                self.fh.write(line + '\n')
                self.fh.flush()

    def close(self):
        with self.lock:
            if self.fh:
                self.fh.close()
                self.fh = None

    def view(self, since=0):
        """State plus log lines from absolute line number `since` on."""
        with self.lock:
            start = max(since - self.dropped, 0)
            return {'kind': self.kind, 'state': self.state, 'step': self.step,
                    'log': self.log[start:], 'logFrom': self.dropped + start,
                    'logTotal': self.dropped + len(self.log), 'logFile': self.logfile,
                    'result': self.result, 'error': self.error}


ROSETTA_CMD = 'softwareupdate --install-rosetta --agree-to-license'
ROSETTA_MSG = ("building from source on this Mac needs Rosetta 2: some of the pinned PlatformIO tools "
               "(the ESP32-C3 compiler and mklittlefs) only come as Intel programs. Install it by running "
               "this in Terminal, then press Install again:  " + ROSETTA_CMD +
               "   Or choose the prebuilt image, which needs nothing extra.")


def needs_rosetta():
    """True on an Apple Silicon Mac that can't run Intel programs; False everywhere else."""
    if sys.platform != 'darwin' or platform.machine() != 'arm64':
        return False
    try:
        return subprocess.call(['arch', '-x86_64', '/usr/bin/true'], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL) != 0
    except OSError:
        return True


CRASH_RE = re.compile(r'Guru Meditation|Backtrace:|abort\(\) was called|Brownout detector|rst:0x[0-9a-f]+ \((?!POWERON)', re.I)


def no_answer_reason(port, opened, open_error, seen, timeout):
    """Why INFO got no answer, from what the port and the board did meanwhile."""
    if not opened:
        why = 'couldn\'t open %s' % port + (': ' + open_error if open_error else '')
        if re.search(r'busy|in use|errno 16|access is denied', open_error or '', re.I):
            return why + '. Another program is using the board: close any serial monitor, Arduino IDE or flasher, then try again.'
        if re.search(r'permission', open_error or '', re.I):
            return why + '. On Linux, run: sudo usermod -aG dialout $USER, then log out and back in.'
        return why + '. Unplug the board, plug it back in, and try again.'
    if not seen:
        return ('the board sent nothing over USB in %d s. Check it is powered and that %s is really the board '
                '(pick another port in step 1 if there are several), then unplug it, plug it back in and try again.' % (timeout, port))
    if sum(1 for l in seen if CRASH_RE.search(l)) >= 2:
        return ('the board keeps crashing and restarting (see what it printed in Details). Press Install in step 3 '
                'to put fresh firmware on it.')
    return ('the board is running, but its firmware doesn\'t answer setup commands: it is probably an older version '
            'of the ad-blocker, or other firmware. Press Install in step 3 to update it (this erases it).')


def explain_failure(log):
    """A plain-language cause for known build failures, or ''."""
    text = '\n'.join(log[-400:])
    if 'Bad CPU type in executable' in text:
        return ROSETTA_MSG
    if 'Permission denied' in text and ('/dev/tty' in text or 'could not open port' in text.lower()):
        return "this computer won't let the helper open the USB port. On Linux, run: sudo usermod -aG dialout $USER, then log out and back in."
    if 'could not open port' in text.lower() or 'Resource busy' in text:
        return 'the USB port is in use. Close any other program using the board (serial monitor, Arduino IDE, another browser tab), then try again.'
    return ''


class Helper:
    def __init__(self):
        self.token = secrets.token_urlsafe(24)
        self.job = None
        self.monitor = None
        self.lock = threading.Lock()

    # ---- environment ----
    def status(self):
        import esptool
        from serial.tools import list_ports
        ports = []
        for p in list_ports.comports():
            if p.vid is None and not re.search(r'usb|acm|COM\d', p.device, re.I):
                continue                                  # skip Bluetooth and built-in ports
            ports.append({'port': p.device, 'desc': p.description or '', 'likely': p.vid in VIDS,
                          'kind': VIDS.get(p.vid, '')})
        ports.sort(key=lambda p: not p['likely'])
        pio = os.path.join(os.path.dirname(venv_python()), 'pio.exe' if os.name == 'nt' else 'pio')
        return {'python': platform.python_version(), 'esptool': getattr(esptool, '__version__', '?'),
                'pio': os.path.exists(pio), 'os': {'darwin': 'mac', 'win32': 'win'}.get(sys.platform, 'linux'),
                'repo': HERE, 'ports': ports, 'job': self.job.state if self.job else None,
                'monitor': self.monitor.port if self.monitor else None,
                'linuxGroups': self.linux_serial_hint(), 'rosetta': {'needed': needs_rosetta(), 'cmd': ROSETTA_CMD}}

    @staticmethod
    def linux_serial_hint():
        if not sys.platform.startswith('linux'):
            return ''
        try:
            import grp
            names = {grp.getgrgid(g).gr_name for g in os.getgroups()}
        except Exception:
            return ''
        return '' if names & {'dialout', 'uucp'} else 'sudo usermod -aG dialout $USER  (then log out and back in)'

    def run(self, job, cmd, env=None, out=None):
        """Run cmd, streaming its output into the job log (and into out, if given)."""
        job.say('$ ' + ' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=HERE, env=env,
                             bufsize=1, universal_newlines=True, encoding='utf-8', errors='replace')
        for line in p.stdout:
            for part in line.rstrip('\n').split('\r'):
                if part.strip():
                    job.say(part.rstrip())
                    if out is not None:
                        out.append(part)
        return p.wait()

    def esptool(self, *args):
        return [sys.executable, '-m', 'esptool'] + list(args)

    def stop_monitor(self):
        if self.monitor:
            self.monitor.close()
            self.monitor = None

    def start_monitor(self, port):
        if self.monitor and self.monitor.port == port:
            return self.monitor
        self.stop_monitor()
        self.monitor = Monitor(port)
        return self.monitor

    def start_job(self, kind, fn, *args):
        with self.lock:
            if self.job and self.job.state == 'running':
                raise RuntimeError('another step is still running')
            job = self.job = Job(kind)

        def go():
            try:
                job.result = fn(job, *args)
                job.state = 'ok'
            except Exception as e:
                why = explain_failure(job.log)
                job.error = why if why and why not in str(e) else str(e)
                job.say('✗ ' + str(e))
                if why and why != str(e):
                    job.say('  likely cause: ' + why)
                job.state = 'error'
            finally:
                job.close()
        threading.Thread(target=go, daemon=True).start()
        return job.view()

    # ---- steps ----
    def detect(self, job, port):
        self.stop_monitor()
        job.step = 'Asking the board what it is'
        out = []
        code = self.run(job, self.esptool('--port', port, 'chip-id'), out=out)
        chip = chip_from_esptool('\n'.join(out))
        if code == 0 and not chip:
            raise RuntimeError('this board is not an ESP32-C3, ESP32-S3 or classic ESP32, which are the ones supported')
        if code != 0:
            raise RuntimeError("couldn't talk to the board on %s. Check the cable carries data, or hold BOOT "
                               "while plugging it in, then try again." % port)
        job.say('✓ found %s' % {'c3': 'ESP32-C3', 's3': 'ESP32-S3', 'esp32': 'ESP32'}[chip])
        return {'chip': chip}

    def fetch(self, job, name):
        import ssl
        import urllib.request
        import certifi
        os.makedirs(CACHE, exist_ok=True)
        ctx = ssl.create_default_context(cafile=certifi.where())
        dest = os.path.join(CACHE, name)
        job.say('downloading %s%s' % (SITE, name))
        with urllib.request.urlopen(SITE + name, context=ctx, timeout=120) as r, open(dest + '.part', 'wb') as f:
            shutil.copyfileobj(r, f)
        os.replace(dest + '.part', dest)
        return dest

    def install(self, job, port, chip, method):
        if chip not in CHIPS:
            raise RuntimeError('unknown board type')
        if chip == 'esp32' and method != 'source':
            raise RuntimeError('the classic ESP32 has no prebuilt image: choose "Build from source"')
        self.stop_monitor()
        if method == 'source':
            self.build_and_flash(job, port, chip)
        else:
            job.step = 'Downloading the firmware'
            name = 'adblock-%s.bin' % chip
            img = self.fetch(job, name)
            sums = open(self.fetch(job, 'SHA256SUMS')).read()
            if not sha256_ok(img, sums, name):
                raise RuntimeError('the download is damaged (checksum mismatch). Try again.')
            job.say('✓ checksum matches')
            job.step = 'Flashing (about a minute)'
            if self.run(job, self.esptool('--chip', CHIPS[chip], '--port', port, 'write-flash', '0x0', img)) != 0:
                raise RuntimeError('flashing failed. Unplug and replug the board, then try again'
                                   + (' (on an S3: hold BOOT, tap RESET, release BOOT).' if chip == 's3' else '.'))
        job.step = 'Waiting for the board to start'
        return self.read_info(job, port, 40)    # first boot makes the TLS key: allow time

    def build_and_flash(self, job, port, chip):
        if needs_rosetta():                              # fail now, not after minutes of downloads
            raise RuntimeError(ROSETTA_MSG)
        env = dict(os.environ)
        import certifi
        env['SSL_CERT_FILE'] = certifi.where()           # python.org Python on macOS has no roots
        pio = os.path.join(os.path.dirname(sys.executable), 'pio.exe' if os.name == 'nt' else 'pio')
        if not os.path.exists(pio):
            job.step = 'Installing PlatformIO (a few minutes, once)'
            if self.run(job, [sys.executable, '-m', 'pip', 'install', '--disable-pip-version-check', '-U', 'platformio']) != 0:
                raise RuntimeError('installing PlatformIO failed')
        secrets_h = os.path.join(HERE, 'src', 'secrets.h')
        if not os.path.exists(secrets_h):
            shutil.copy(os.path.join(HERE, 'src', 'secrets.example.h'), secrets_h)
            job.say('created src/secrets.h from the example (WiFi and passwords come over USB instead)')
        bl = os.path.join(HERE, 'data', 'blocklist.bin')
        if not os.path.exists(bl):
            job.step = 'Building the blocklist'
            if self.run(job, [sys.executable, os.path.join('tools', 'build_blocklist.py'), bl], env) != 0:
                raise RuntimeError('building the blocklist failed (see the log)')
        e = ENVS[chip]
        job.step = 'Building and flashing the firmware (several minutes the first time)'
        if self.run(job, [pio, 'run', '-e', e, '-t', 'upload', '--upload-port', port], env) != 0:
            raise RuntimeError('building or flashing the firmware failed (see the log)')
        job.step = 'Flashing the blocklist'
        if self.run(job, [pio, 'run', '-e', e, '-t', 'uploadfs', '--upload-port', port], env) != 0:
            raise RuntimeError('flashing the blocklist failed (see the log)')

    def read_info(self, job, port, timeout):
        mon = self.start_monitor(port)
        first = mon.mark()
        end = time.time() + timeout
        job.say('asking the board for its status on %s (up to %d s)' % (port, timeout))
        while time.time() < end:
            start = mon.mark()
            mon.send('INFO\n')
            info = mon.wait_for(start, parse_info, 3)
            if info:
                job.say('✓ board is up (%s mode)' % ('setup' if info['mode'] == 'setup' else 'online')
                        + (', free memory %d KB, largest block %d KB' % (info['heap'] // 1024, info['maxblock'] // 1024)
                           if 'heap' in info else ''))
                return info
        seen = mon.lines_since(first)
        if seen:
            job.say('--- what the board printed (%d lines) ---' % len(seen))
            for l in seen[-80:]:
                job.say('  ' + l)
            job.say('--- end ---')
        raise RuntimeError(no_answer_reason(port, mon.ser is not None, mon.open_error, seen, timeout))

    def info(self, job, port):
        job.step = 'Asking the board for its status'
        return self.read_info(job, port, 25)

    def nets(self, port):
        mon = self.start_monitor(port)
        for _ in range(3):
            start = mon.mark()
            mon.send('NETS\n')
            r = mon.wait_for(start, lambda l: parse_nets(l) if l.startswith('[nets]') else None, 3)
            if r is not None:
                return r
        return []

    def provision(self, job, port, ssid, wifi_pass, admin, current):
        line = provision_line(ssid, wifi_pass, admin, current)    # validates before anything is sent
        mon = self.start_monitor(port)
        job.step = 'Sending your settings to the board'
        start = mon.mark()
        if not mon.send(line):
            raise RuntimeError('lost the USB connection to the board')

        def answer(l):
            if l.startswith('[provision] ok'):
                return 'ok'
            if l.startswith('[provision] error'):
                return l[len('[provision] error'):].strip()
            return None
        r = mon.wait_for(start, answer, 10)
        if r is None:
            raise RuntimeError("the board didn't answer. Is it still in setup mode? Press Check on step 1.")
        if r != 'ok':
            raise RuntimeError(r.split(' ', 1)[-1])
        job.say('✓ settings saved on the board')
        job.step = 'Joining "%s" (up to 40 seconds)' % ssid
        # Scan from when PROVISION went out: on a fast network "WiFi up" can arrive in the
        # same burst as "[provision] ok". Neither line can appear before the command.

        def joined(l):
            m = UP_RE.match(l)
            if m:
                return ('up', m.group(1))
            if l.startswith('[setup] No WiFi'):
                return ('fail', '')
            return None
        r = mon.wait_for(start, joined, 60)
        if not r:
            raise RuntimeError("the board hasn't reported back. It may still be joining: press Check on step 1 in a minute.")
        if r[0] == 'fail':
            raise RuntimeError("the board couldn't join \"%s\". Check the WiFi name and password (it needs a 2.4 GHz "
                               "network) and try again." % ssid)
        job.say('✓ joined, address %s' % r[1])
        time.sleep(2)
        info = self.read_info(job, port, 15)
        info['ip'] = info.get('ip') or r[1]
        return info


# ---------------------------------------------------------------- HTTP

def make_handler(helper, port):
    from http.server import BaseHTTPRequestHandler

    class H(BaseHTTPRequestHandler):
        server_version = 'c3adblock-setup'

        def log_message(self, *a):
            pass                                          # keep the terminal quiet (and passwords out of it)

        def send_json(self, code, obj, extra=None):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-store')
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def guard(self):
            if not host_ok(self.headers.get('Host', ''), port):
                self.send_json(403, {'error': 'wrong host'})
                return False
            if self.path.startswith('/api/') and not secrets.compare_digest(self.headers.get('X-Setup-Token', ''), helper.token):
                self.send_json(403, {'error': 'missing or wrong token: reload the page'})
                return False
            return True

        def do_GET(self):
            if self.path == '/ping':                      # lets the file:// copy of the page find us; no data
                return self.send_json(200, {'helper': True, 'port': port}, {'Access-Control-Allow-Origin': '*'})
            if not self.guard():
                return
            if self.path in ('/', '/index.html'):
                html = open(PAGE, encoding='utf-8').read()
                cfg = '<script>window.HELPER=%s;</script>' % json.dumps({'token': helper.token})
                body = html.replace('<!--HELPER-->', cfg, 1).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
            if self.path == '/api/status':
                return self.send_json(200, helper.status())
            if self.path.startswith('/api/job'):
                m = re.search(r'[?&]since=(\d+)', self.path)
                return self.send_json(200, helper.job.view(int(m.group(1)) if m else 0) if helper.job else {})
            if self.path == '/api/console':
                return self.send_json(200, {'lines': helper.monitor.tail() if helper.monitor else []})
            self.send_json(404, {'error': 'not found'})

        def do_POST(self):
            if not self.guard():
                return
            try:
                n = int(self.headers.get('Content-Length', '0'))
                req = json.loads(self.rfile.read(min(n, 65536)) or b'{}')
                port_ = str(req.get('port', ''))
                if self.path == '/api/detect':
                    return self.send_json(200, helper.start_job('detect', helper.detect, port_))
                if self.path == '/api/install':
                    return self.send_json(200, helper.start_job('install', helper.install, port_,
                                                                str(req.get('chip')), str(req.get('method'))))
                if self.path == '/api/info':
                    return self.send_json(200, helper.start_job('info', helper.info, port_))
                if self.path == '/api/send':
                    line = console_command(str(req.get('cmd', '')))
                    if helper.job and helper.job.state == 'running':
                        raise RuntimeError('wait for the current step to finish')
                    mon = helper.start_monitor(port_)
                    if not mon.send(line):
                        raise RuntimeError("couldn't write to the board: " + (mon.open_error or 'port not open'))
                    return self.send_json(200, {'sent': line.strip()})
                if self.path == '/api/nets':
                    return self.send_json(200, {'nets': helper.nets(port_)})
                if self.path == '/api/provision':
                    provision_line(str(req.get('ssid', '')), str(req.get('pass', '')), str(req.get('admin', '')),
                                   str(req.get('current', '')))      # reject bad input before starting
                    return self.send_json(200, helper.start_job(
                        'provision', helper.provision, port_, str(req.get('ssid', '')), str(req.get('pass', '')),
                        str(req.get('admin', '')), str(req.get('current', ''))))
                self.send_json(404, {'error': 'not found'})
            except (ValueError, RuntimeError) as e:
                self.send_json(400, {'error': str(e)})

    return H


def serve():
    from http.server import ThreadingHTTPServer
    helper = Helper()
    for port in PORTS:
        try:
            srv = ThreadingHTTPServer(('127.0.0.1', port), make_handler(helper, port))
            break
        except OSError:
            continue
    else:
        sys.exit('No free port between %d and %d.' % (PORTS[0], PORTS[-1]))
    url = 'http://127.0.0.1:%d/' % port
    print('\nC3 AdBlock setup is running at %s' % url, flush=True)
    print('Your browser should open it now. If not, copy that address into it.', flush=True)
    print('Leave this window open while you set up. Press Ctrl+C here when you are done.\n', flush=True)
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped. You can close this window.')
    finally:
        helper.stop_monitor()


if __name__ == '__main__':
    bootstrap()
    serve()
