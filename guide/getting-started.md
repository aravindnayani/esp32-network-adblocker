# Getting started: the steps behind START-HERE.html

[← Back to README](../README.md)

> **For maintainers.** Users are pointed at [`START-HERE.html`](../START-HERE.html), an interactive page that shows only the steps for their board, install method, OS and browser. This file lists every step and branch in one place so the page's content can be reviewed and changed. **When you change a step here, change the page too, and the other way round.**

## The choices

| Choice | Options | Effect |
|---|---|---|
| Board | ESP32-C3 4 MB (default) · ESP32-S3 8 MB+ · classic ESP32 4 MB | chip name, esptool `--chip`, PlatformIO env (`c3`, `s3`, `esp32dev`), merged image name. Classic ESP32 forces *build from source*. |
| Install method | Prebuilt image (default) · Build from source | Source adds the *secrets* step and uses PlatformIO. |
| OS | macOS · Windows · Linux (auto-detected) | Shell syntax (PowerShell on Windows), port names, checksum tool, `dig` vs `nslookup`. |
| Browser | Chrome · Edge · Safari · Firefox (auto-detected) | In-browser flashing or esptool, and certificate-warning steps. |
| Blocklist | Default ~100k · Everything ~500k (S3 only) | Adds the *load the everything list* step (prebuilt) or extra sources to the build (source). |

**Web Serial decides the flashing route.** Desktop Chrome and Edge always get the one-click web installer. Safari has no Web Serial; Firefox counts only if `'serial' in navigator` is true in the browser actually running the page. Without it, the page uses esptool and the merged images that `flasher.yml` publishes next to the installer (`adblock-c3.bin`, `adblock-s3.bin`, `SHA256SUMS`).

The page stores the five choices in the URL hash and in `localStorage` (with the per-step ticks). Values typed into the secrets form are never stored or sent.

## Steps

### 1. Get your hardware ready
- The board and a USB cable that carries data.
- S3 with two ports: use the one labelled **USB**, not **UART**.
- C3/S3: no driver. Classic ESP32 on macOS/Windows: CP210x or CH340 driver (chip name is next to the USB port). Linux has both built in.
- Source build: the cloned repository.

### 2. Fill in your secrets *(build from source only, all optional)*
Generates `src/secrets.h` in the format of [`src/secrets.example.h`](../src/secrets.example.h):

| Field | Becomes | If left empty |
|---|---|---|
| Fallback WiFi name / password | `WIFI_SSID` / `WIFI_PASS` | placeholders, so no fallback WiFi |
| Admin user | `WEB_USER` | `admin` |
| Admin password (8+) | `WEB_PASS` | placeholder, so it's chosen in the setup portal |
| OTA password (8+) | `OTA_PASS` | placeholder, so it's the admin password |

Strings are escaped as C literals (`\\`, `\"`, control bytes as 3-digit octal). Downloaded as `secrets.h`, or copied.

### 3. Flash the board

**Prebuilt, browser with Web Serial:** open the [web installer](https://aravindnayani.github.io/esp32-network-adblocker/), **⚡ Connect & Install**, pick the port, install (erase if asked), keep the tab open.

**Prebuilt, no Web Serial (Safari, Firefox):** in a working folder (`~/c3-adblock`):

```bash
python3 -m venv venv
./venv/bin/python -m pip install "esptool>=5"
curl -fLO https://aravindnayani.github.io/esp32-network-adblocker/adblock-c3.bin
curl -fLO https://aravindnayani.github.io/esp32-network-adblocker/SHA256SUMS
grep ' adblock-c3.bin$' SHA256SUMS | shasum -a 256 -c      # Linux: sha256sum -c
./venv/bin/python -m esptool --chip esp32c3 write-flash 0x0 adblock-c3.bin
```

Windows (PowerShell) uses `py -m venv venv`, `.\venv\Scripts\python`, `Invoke-WebRequest … -OutFile …`, and compares `(Get-FileHash adblock-c3.bin).Hash` with the line in `SHA256SUMS`. For the S3: `adblock-s3.bin` and `--chip esp32s3` (if it won't connect, hold BOOT, tap RESET, release BOOT). An optional `--port` can be filled in on the page. The merged image covers the whole flash from `0x0`, so it also wipes saved settings.

**Build from source:** from the repo folder:

```bash
python3 -m venv .venv && source .venv/bin/activate     # Windows: py -m venv .venv; .\.venv\Scripts\Activate.ps1
python -m pip install -U platformio
mv ~/Downloads/secrets.h src/secrets.h                  # or: cp src/secrets.example.h src/secrets.h
python tools/build_blocklist.py data/blocklist.bin      # + the two "everything" URLs on S3, see building.md
pio run -e c3 -t upload
pio run -e c3 -t uploadfs
```

Env is `c3`, `s3` or `esp32dev`. Notes shown on the page: python.org Python on macOS needs *Install Certificates.command* for `CERTIFICATE_VERIFY_FAILED`; Linux ModemManager fix is in [building.md](building.md#troubleshooting).

### 4. Get the setup password
Each boot prints, and the portal repeats every 15 s:

```
[setup] setup WiFi (if it's ever needed): "C3-AdBlock-1A2B", password abcd-efgh-jkmn
[https] certificate SHA-256 fingerprint: …
```

- Web Serial: installer → **Logs & Console** (Reset device if empty).
- esptool route: `./venv/bin/python -m serial.tools.miniterm - 115200` (pick the port; quit with Ctrl+]), then press RESET.
- Source: `pio device monitor -e c3`.
- If `secrets.h` has a fallback WiFi and the device joins it, there's no setup WiFi; the console shows `WiFi up: <ip>`.

### 5. Connect it to your WiFi and choose an admin password
Join `C3-AdBlock-XXXX` with the setup password, the portal opens (or `http://192.168.4.1`). Pick home WiFi (2.4 GHz), enter its password, choose an admin password (8+, user `admin` or `WEB_USER`), check the fingerprint, **Connect**. If the device joined a fallback WiFi directly: admin password is `WEB_PASS`, or, if none was set, hold BOOT while plugging in to open setup.

### 6. Open the dashboard
`https://c3adblock.local` (or the IP: some Android phones and older Windows can't resolve `.local`). Accept the self-signed certificate after checking its SHA-256 fingerprint:

| Browser | Check fingerprint | Accept |
|---|---|---|
| Chrome | *Not secure* badge → Certificate details | Advanced → Proceed to c3adblock.local (unsafe) |
| Edge | *Not secure* → Your connection to this site isn't secure → certificate icon | Advanced → Continue to c3adblock.local (unsafe) |
| Firefox | Advanced… → View Certificate → Fingerprints | Accept the Risk and Continue |
| Safari | Show Details → view the certificate → Details | visit this website → Visit Website (may ask for the macOS password) |

### 7. Turn it on for your network
Set one device's DNS first if you like, then the router's DNS (DHCP/LAN settings), and reserve the device's IP. Check: `dig +short @<ip> doubleclick.net` (Windows: `nslookup doubleclick.net <ip>`) returns `0.0.0.0`.

### 8. Load the "everything" list *(S3 + Everything only)*
Source builds already have it. Prebuilt: `python3 tools/build_blocklist.py blocklist.bin <the two URLs>`, then dashboard → **Blocklist → Upload**, press BOOT.

### 9. Keep it running
Same table as the README's *Everyday use*: weekly auto-update URL, pause, custom domains, ban, OTA, forget WiFi, BOOT-at-power-on recovery. Power and case tips.
