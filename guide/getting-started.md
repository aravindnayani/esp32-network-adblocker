# Getting started: the steps behind the setup page

[← Back to README](../README.md)

> **For maintainers.** Users only see the interactive page: [`START-HERE.html`](../START-HERE.html), served by [`start-here.py`](../start-here.py), and then the device's own dashboard (`src/page.h`). This file lists every step and branch in one place so the flow can be reviewed. **When you change a step here, change the page, the helper or the dashboard too, and the other way round.**

## The pieces

| Piece | Role |
|---|---|
| `START-HERE.html` opened from disk | Step 1 only: install Python (and git) per OS, run `start-here.py`, then check from the browser that the helper is running (probes `http://127.0.0.1:8765-8775/ping`). Fallback for people without Python: the Chrome/Edge web installer + setup WiFi. |
| `start-here.py` | Creates `.setup-venv/` (esptool 5.5.0 + certifi), serves the page on `127.0.0.1` with a per-run token, and does the USB work: list ports, detect the chip, download + checksum + flash (or build with PlatformIO), and `INFO` / `NETS` / `PROVISION` over the USB console. |
| `START-HERE.html` served by the helper | Steps 1–6 below, driven through the helper's API. |
| Dashboard (`https://c3adblock.local`) | "Finish setting up" card: what to block, exceptions, router DNS, check. Then the "How to use & update" help. |

Works the same in Chrome, Edge, Safari and Firefox: the page itself uses no Web Serial, only `fetch` to the helper.

## Before the helper: install the basics (terminal)

| OS | What the user does |
|---|---|
| macOS | Terminal → `python3 --version` (accept the developer-tools prompt if it appears, which also gives git) → `git clone …` → `cd esp32-network-adblocker` → `python3 start-here.py` |
| Windows | Install Python from python.org with **Add python.exe to PATH** → download + extract the ZIP → PowerShell → `cd …\esp32-network-adblocker-main` → `py start-here.py` |
| Linux | `sudo apt install python3 python3-venv git` → `sudo usermod -aG dialout $USER` (log out/in) → clone → `python3 start-here.py` |

The helper prints its address and opens the browser itself. The file:// page also shows a **Continue setup →** button once its probe finds the helper; when a browser blocks that probe (Safari from a file), it links to `http://127.0.0.1:8765/` instead.

## Steps in the helper page

### 1. Check your computer and plug in the board
Shows Python and esptool versions (from `/api/status`) and lists USB serial ports, polling every 2.5 s. Espressif's own USB (VID 303a) and CP210x/CH340/FTDI ports count as likely boards. On Linux without `dialout`/`uucp`, shows the `usermod` command. With one port, step 2 starts by itself.

### 2. Your board
`/api/detect` runs `esptool chip-id` and maps the answer to `c3`, `s3` or `esp32` (classic, any package). Other chips (S2, C6, H2 …) are refused. The user can override the choice. Method: **Prebuilt** (default) or **Build from source**; the classic ESP32 forces source. **Ask the board for its status** sends `INFO`, for a board that's already flashed: online → jump to step 5; setup mode → step 4.

### 3. Install
- **Prebuilt:** download `adblock-<chip>.bin` and `SHA256SUMS` from the Pages site (`flasher.yml` builds them), check the hash, `esptool --chip esp32<chip> --port P write-flash 0x0 adblock-<chip>.bin`. This wipes the whole flash, settings included.
- **Source:** on an Apple Silicon Mac without Rosetta 2, stop straight away and show `softwareupdate --install-rosetta --agree-to-license` (step 1 shows the same check, and Install stays disabled for source builds until it passes). Then `pip install platformio` into `.setup-venv` if needed, copy `secrets.example.h` to `secrets.h` if missing, build `data/blocklist.bin` if missing, then `pio run -e <c3|s3|esp32dev> -t upload` and `-t uploadfs` on that port.

Every step's log is kept in full: the page fetches it incrementally (`/api/job?since=N`) into **Details — full log** with Copy and Save buttons, and the helper also writes it to `.setup-cache/logs/<time>-<step>.log`. Known failures (Intel-only tools, a busy or forbidden USB port) get a plain-language cause.

Then it waits up to 40 s for `INFO` to answer (the first boot creates the TLS key).

### 4. Your WiFi and admin password
`NETS` fills the WiFi-name suggestions with what the board scanned. The page checks: name 1–32 bytes, WiFi password empty or 8–63, admin password 8+ and typed twice. If `INFO` says an admin password is already set (setup mode after a failed join), the page also asks for the current one. **Connect** sends `PROVISION` (all fields hex), waits for `[provision] ok`, then for `WiFi up: <ip>` (joined) or `[setup] No WiFi` (wrong password or no 2.4 GHz network: the user can retry). Passwords are cleared from the form afterwards.

### 5. Open the dashboard
Shows `https://c3adblock.local`, the IP link and the certificate fingerprint from `INFO`, plus how to check the fingerprint and accept the warning:

| Browser | Check fingerprint | Accept |
|---|---|---|
| Chrome | *Not secure* badge → Certificate details | Advanced → Proceed to c3adblock.local (unsafe) |
| Edge | *Not secure* → Your connection to this site isn't secure → certificate icon | Advanced → Continue to c3adblock.local (unsafe) |
| Firefox | Advanced… → View Certificate → Fingerprints | Accept the Risk and Continue |
| Safari | Show Details → view the certificate → Details | visit this website → Visit Website |

### 6. Using it and keeping it up to date
Daily use, automatic blocklist updates, firmware OTA + BOOT press, Forget WiFi then rerun the helper, BOOT-at-power-on recovery, then Ctrl+C the helper and move the board to the router.

## On the dashboard: Finish setting up

A card at the top (hidden once the user clicks **I'm done**, remembered per browser) with three checks it ticks by itself:

1. **Choose what to block** — done when the auto-update URL is one of this project's weekly lists.
2. **Send your network's DNS here** — router DNS (or one device) → the device IP; done when another device has made queries.
3. **Check it works** — done when the browsing device's own IP has made queries.

**What to block** — ads, trackers & malware always on; tick social media, gambling, adult content, fake news. **Apply** asks for a BOOT press (it's a new update URL), sets `…/releases/download/blocklist/blocklist[-<cats>].bin` with a 24 h interval, then fetches it straight away. `<cats>` are the ticked categories in the fixed order `fakenews, gambling, porn, social`; `blocklist.yml` builds all 16 combinations every Monday (largest ~179k entries, so all fit the C3).

**Exceptions** — `/allow` and `/unallow` (password only, audit-logged), max 100, matched like custom domains including subdomains, and checked before any block. Quick picks add each app's domains: WhatsApp, Instagram, Facebook, YouTube, TikTok, X, Reddit, LinkedIn, Discord, Snapchat.

**How to use & update** — at the bottom of the dashboard: daily use, fixing a broken site (exception or pause), bans, lost password, automatic blocklist updates, firmware OTA, moving house.
