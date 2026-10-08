# esp32-network-adblocker

A **Pi-hole-style DNS ad-blocker** that runs on a **$2 ESP32-C3**, with *no PSRAM required*.

> 📰 The upstream project was featured on [Tom's Hardware](https://www.tomshardware.com/networking/clever-hacker-fits-537-000-domains-in-a-tiny-usd5-esp32-ad-blocking-dongle-firmware-uses-only-around-50kb-of-ram-and-can-answer-blocked-lookups-in-10-milliseconds), [XDA Developers](https://www.xda-developers.com/this-tiny-esp32-powered-gadget-blocks-537000-domains-only-uses-50kb-of-ram/), and [Korben](https://korben.info/en/half-million-ad-blocking-domains-50kb-ram-esp32.html).

The trick everyone misses: the blocklist doesn't have to live in RAM. Store the
domains as **sorted 40-bit hashes in flash** and search them there. 140,000+ domains
fit in ~0.7 MB of flash, lookups take ~10 ms, and the firmware uses **~50 KB of RAM**.

```
query in ──▶ extract domain ──▶ FNV-1a hash (+ parent suffixes)
         ──▶ custom list? ──▶ RAM cache? ──▶ RAM index → one flash read of the bucket
              ├─ hit  ──▶ answer 0.0.0.0   (sinkholed)
              └─ miss ──▶ forward to upstream resolver (Quad9), relay the reply
```

## Contents

- [What's Changed](#whats-changed)
- [Features](#features)
- [How it works](#how-it-works)
- [Hardware](#hardware)
- [Quick start: browser installer](#quick-start-browser-installer)
- [Build & flash from source (PlatformIO)](#build--flash-from-source-platformio)
- [First-time setup](#first-time-setup)
- [Use it](#use-it)
- [Over-the-air updates](#over-the-air-updates)
- [Configuration reference](#configuration-reference)
- [Security](#security)
- [CI / GitHub Actions](#ci--github-actions)
- [Project layout](#project-layout)
- [Gotchas](#gotchas)
- [Roadmap](#roadmap)
- [Inspiration & Thanks](#inspiration--thanks)
- [License](#license)

---

## What's Changed

This repository builds on [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock).
It changes how the admin password is set and hardens the dashboard further. The goal is a
prebuilt, credential-free image that anyone can flash from the browser and that stays
safe to use.

### 🔐 Admin password chosen on the device, with no default credentials
- **The setup portal now asks for a dashboard admin password** (8+ characters, user `admin`)
  next to the WiFi details. It is stored in NVS (`auth` namespace), so you no longer need
  to put a password in `secrets.h` and rebuild.
- **The placeholder passwords are ignored.** `CHANGE_ME_WEB_PASSWORD` and
  `CHANGE_ME_OTA_PASSWORD` are public, so the firmware treats them as "no password".
  Upstream booted with them and only showed a warning.
- **Locked until a password exists.** If no password is set in the portal or in
  `secrets.h`, every state-changing endpoint returns `403 no admin password set`. The
  dashboard then shows a banner explaining how to set one.
- **Precedence:** the portal password (NVS) comes first. A real `WEB_PASS` in `secrets.h`
  is used only when NVS has none, so source builds still work.
- On **Forget WiFi**, the portal keeps the current admin password. Leave the field blank
  to keep it, or type a new one to replace it.

### 📡 Network OTA is password-gated or off
- `ArduinoOTA` **only starts when there is a password.** If `OTA_PASS` is left as the
  placeholder, it uses the admin password. With no password at all, network OTA is
  never started, and `loop()` skips `ArduinoOTA.handle()`.

### 🛡️ DNS-rebinding protection
- A new `Host`-header check (`hostOk()` / `requireHost()`) runs on `/`, `/stats.json`, and
  every authenticated endpoint. Only `c3adblock.local`, `c3adblock`, or the device's own
  IP are accepted. Anything else gets `403 bad Host header`, so a rebinding page can't
  read stats or get past the CSRF header check.

### 👆 BOOT button approves risky actions
- **Firmware upload, blocklist upload, a new remote-update URL, Forget WiFi, and pausing
  blocking indefinitely or for more than 30 minutes** now need a press of the device's **BOOT** button as well as the password. The dashboard asks the device
  to wait (`/confirm`), the LED blinks, and a press within 30 s approves that one action, for
  that one client, for 60 s. Software that has your password can't do these on its own: an AI
  browser agent in a logged-in tab, a prompt-injected script, or someone who sniffed the LAN.
- While it's on, **network OTA** (`espota`) only answers for 60 s after a BOOT press made with
  nothing pending.
- It can be turned off under **Security** on the dashboard (turning it off needs a press too).
  BOOT-at-power-on recovery turns it back on.

### 🚫 Login lockout
- After **5 wrong passwords** from one IP, that IP gets `429` for 30 s, doubling with each
  further failure up to 1 h. A correct password resets the count. Locked-out clients are
  listed on the dashboard.
- A **device-wide limit** stops guessing spread over many IPs: about 20 wrong passwords in a
  burst, then one per 45 s across the whole network. Pressing **BOOT** (with nothing waiting
  for approval) clears all lockouts.

### 📜 Audit log
- The last **32 admin events** (actions, wrong passwords, lockouts, confirmations, BOOT
  presses) are kept in RAM with time, client IP and MAC, and shown on the dashboard. The log
  is cleared on reboot.

### 🔁 BOOT button = full recovery
- Holding **BOOT** while powering on now clears the saved WiFi **and the admin password**,
  then **always opens the setup portal**, even when `secrets.h` has fallback WiFi
  credentials. Physical access is how you recover a forgotten password.

### 🧩 Upload / OTA auth fixes
- Blocklist (`/upload`) and firmware (`/update`) uploads use a shared `authOk()` check
  (Host + password set + CSRF header + Basic Auth).
- The per-upload auth flags (`upAuthOk`, `fwAuthOk`) are **reset after every request**,
  so one authenticated upload can't leave a later request authorized.
- A failed upload now gets the correct response (`403` / auth challenge). An
  authenticated request with no file gets `400 no file received` instead of a bare
  auth prompt.

### 🖥️ Dashboard & docs
- `/stats.json` reports `noauth` (no admin password set) instead of `defcreds`. The
  banner now explains how to fix it ("hold BOOT, join `C3-AdBlock-XXXX`…").
- `secrets.example.h` now states that **every value in it is optional**.
- The Security docs now list `/pause` and `/resume` (which were already authenticated),
  explain the OTA fallback, and cover DNS rebinding.
- The Japanese README (`README_JP.md`) was removed. It described the old password setup,
  and this README is now the only documentation.

### 🔏 Verified blocklist downloads
- Remote blocklist URLs must be **https://**. `setInsecure()` is gone: the server
  certificate and hostname are checked against a 6 KB bundle of 16 major root CAs
  (`src/ca_bundle.h`, generated by `tools/gen_ca_bundle.py`). The full Mozilla bundle
  (~63 KB) wouldn't fit next to two firmware slots.

### 🧱 Safe blocklist swaps
- A new list is checked before it goes live: declared size reached (no truncated
  downloads), whole 5-byte entries, and sorted. If both lists fit in flash, the old one
  keeps blocking during the transfer and survives a rejected one.
- Downloads handle chunked responses, and uploads catch "flash full" write errors.

### ⚡ DNS never waits on anything else
- DNS runs in **its own FreeRTOS task** on non-blocking sockets. A blocklist download,
  a browser upload, or a firmware flash no longer stops name resolution for the network.
- Upstream forwarding is **asynchronous**: up to 32 queries in flight, each matched by
  txid + question when the reply arrives. A slow upstream answer used to stall *every*
  client for up to 1 s. Now a full table answers SERVFAIL so clients fail over.

### 🚪 No more open resolver
- DNS queries are answered only for clients on the device's own subnet or in private
  ranges (10/8, 172.16/12, 192.168/16, CGNAT 100.64/10, link-local). Anything else is
  **dropped silently**, so a forwarded or exposed port 53 can't be used as an open
  resolver or for amplification attacks. The dashboard shows a "Dropped (non-local)" count.
- Build with `-DDNS_SUBNET_ONLY` to accept only the device's own subnet.

### ⚙️ New CI: browser-flasher build & deploy (`.github/workflows/flasher.yml`)
- Builds the ESP Web Tools images (`firmware.bin`, `littlefs.bin`, bootloader,
  partitions, `boot_app0.bin`, `manifest.json`) **from source on every push to `main`**
  and deploys them to **GitHub Pages**. Previously, `.bin` files committed by hand went
  stale, and the published firmware predated dashboard auth entirely.
- Builds with **placeholder secrets on purpose**, so the images carry no credentials.
- Includes **sanity checks** that fail the deploy if the firmware lacks the auth / CSRF /
  Host-check code, or if the manifest's flash offsets don't match `partitions.csv`.
- Stamps the manifest version as `YYYY.MM.DD-<sha>`.

> One-time setup in your fork: **Settings → Pages → Build and deployment → Source: "GitHub Actions"**.

---

## Features

- 🚫 **DNS sinkhole.** Blocked domains (and their subdomains) answer `0.0.0.0`. Everything
  else is forwarded to Quad9 (`9.9.9.9`, changeable at build time).
- 💾 **Hash-in-flash blocklist.** ~140k domains by default, up to ~250k with firmware OTA,
  ~537k with the single-app layout.
- 📊 **Web dashboard** at `http://c3adblock.local`. Shows per-client block/allow counts,
  RSSI, temperature, heap, and uptime.
- ⏸️ **Pause blocking** for a set time (Pi-hole-style "disable for 5 minutes").
- 🙅 **Ban a client** and **add/remove custom blocked domains** from the browser.
- 📶 **Captive-portal WiFi setup.** No hard-coded credentials.
- 🔄 **OTA everything.** Upload a blocklist or firmware from the dashboard, push firmware
  over WiFi with `espota`, or let the device fetch a blocklist URL on a schedule.
- 🔐 **Hardened admin API.** Basic Auth, a CSRF header, a Host-header check, and no
  default passwords.
- ⚡ **One-click browser installer** (ESP Web Tools), built and deployed by CI.
- 🧩 Runs on **ESP32-C3** (primary) and **classic ESP32** (`esp32dev`).

## How it works

Most ESP32 DNS sinkholes load the blocklist (domain *strings*) into RAM, so they
need PSRAM. This project stores fixed **5-byte (40-bit) FNV-1a hashes in flash** instead:

| | string-in-RAM approach | this (hash-in-flash) |
|---|---|---|
| Hardware | ESP32 + PSRAM (~$8) | ESP32-C3, no PSRAM (~$2) |
| 141k domains | ~2.5 MB of RAM | **0.67 MB of flash** |
| RAM used | most of it | **~50 KB** |
| Lookup | string compare | RAM index + 1 flash read (~10 ms incl. WiFi RTT) |
| Collisions | n/a | 0 at 141k (1 at 537k) |

**Lookup path:**
1. The queried name is hashed, and so is each parent suffix (`a.b.example.com` →
   `b.example.com` → `example.com`). Blocking a domain therefore blocks its subdomains.
2. **Custom domains** added from the dashboard are checked first.
3. A **256-slot direct-mapped RAM cache** answers repeat queries.
4. A **4096-entry first-level index in RAM** (20 KB of evenly spaced sample hashes)
   narrows the search to one small bucket. That bucket is read from flash in a single
   read and scanned.

**Forwarding path:** DNS has its own task, so the dashboard, uploads, and blocklist
downloads in `loop()` can't delay it. An allowed query is sent upstream with a fresh
random txid and recorded in a 32-slot table. When a reply arrives, it's relayed only if
it comes from the upstream address and its txid and question match a recorded query.
Unanswered entries expire after 2.5 s (the client retries). If all slots are busy, the
query gets an immediate SERVFAIL, so the client can fail over to a secondary resolver.

**Why 40 bits?** It suits this flash budget. Collisions follow the birthday bound: at
141k domains you get ~0, and at 537k about 1 (one unlucky domain gets over-blocked).
32 bits would save 20% of the flash but cost ~7 collisions at 250k. 64 bits would spend
3 extra bytes per domain on a problem you don't have.

The same approach works on bigger chips too; it isn't a C3 workaround. On a 16 MB
ESP32-S3, these hashes hold **~2.7M domains**, versus ~466k domain strings in 8 MB of
PSRAM.

## Hardware

- Any **ESP32-C3** board (tested on a C3 SuperMini), 4 MB flash, **no PSRAM needed**.
- **Classic ESP32** (DevKit / WROOM, 4 MB) also builds: `pio run -e esp32dev -t upload`
  (community-contributed and compile-tested; the C3 is the tested target).
- Power it from a **stable USB source** (a phone charger or your router's USB port).
  Cheap or loose USB-C→A adapters can brown out the radio during WiFi transmit.
- A **USB-A → USB-C dongle** lets it plug straight into the spare USB port on the back of
  most routers, with no power supply or extra box.

### Enclosure

A printable case for the C3 SuperMini: [`hardware/esp32-c3-supermini-enclosure.stl`](hardware/esp32-c3-supermini-enclosure.stl)

- No supports needed; 0.2 mm layers and ~15% infill are plenty.
- **Keep the antenna end clear.** The PCB antenna is the zig-zag trace on the short edge
  opposite the USB-C port. Don't bury it in solid plastic or put metal near it.
- Leave the vents open: the board idles around 45–55 °C.

## Quick start: browser installer

No toolchain needed. Open the GitHub Pages site for this repo (`docs/index.html`,
deployed by the [flasher workflow](#ci--github-actions)) in **Chrome or Edge on a
desktop**:

1. Plug in the ESP32-C3 and click **⚡ Connect & Install**.
2. It flashes the firmware and a bundled blocklist (~30 s).
3. Continue with [First-time setup](#first-time-setup).

The prebuilt image contains **no WiFi credentials and no passwords**. You choose both on
the device.

## Build & flash from source (PlatformIO)

You flash over USB once. After that, **firmware and blocklist both update over WiFi**.

> ⚠️ Use a **current PlatformIO**: the VS Code PlatformIO extension's bundled core, or
> `pip install -U platformio` in a venv. The distro/apt `platformio` package (e.g. 4.3.4)
> is too old and fails with `AttributeError: ... 'resultcallback'`.
>
> For the exact build CI produces, install the pinned, hash-checked PlatformIO in a venv with
> `pip install --require-hashes -r tools/requirements-ci.txt`. The platform, Arduino framework,
> toolchains and tools are pinned to exact versions in `platformio.ini`, and the GitHub Actions
> are pinned to commit SHAs.

```bash
# 1. Copy the secrets template (gitignored). Everything in it is OPTIONAL:
#    - WIFI_SSID / WIFI_PASS: fallback WiFi; otherwise use the setup portal.
#    - WEB_PASS / OTA_PASS: placeholders are ignored; the admin password is
#      normally chosen in the setup portal.
cp src/secrets.example.h src/secrets.h

# 2. Build the blocklist hash table (default = StevenBlack base + Hagezi Light,
#    ~100k entries, safe for WhatsApp/social)
python3 tools/build_blocklist.py data/blocklist.bin

# 3. Flash firmware + the blocklist filesystem
pio run -t upload
pio run -t uploadfs

# 4. Watch it boot and note the IP
pio device monitor          # -> http://c3adblock.local
```

For the classic ESP32, add `-e esp32dev` to the `pio` commands.

### Your own blocklists

`build_blocklist.py OUT.bin [SOURCE ...]` takes any mix of URLs and local files in these
formats:

- **hosts files**: `0.0.0.0 ads.example.com tracker.example.com` (all domains on the line are included)
- **plain domain lists**: one domain per line
- **AdGuard / Adblock basic rules**: `||ads.example.com^` blocks, `@@||ok.example.com^`
  removes a domain (e.g. to mirror an AdGuard Home allowlist)

A blocked domain also blocks its subdomains. Rules a DNS hash list can't express (regex,
wildcards, `$` modifiers, cosmetic `##` rules) are skipped and counted. An `@@` rule only
un-blocks that exact entry; it can't carve a subdomain out of a blocked parent. If a
source can't be downloaded, the build stops instead of silently producing a smaller list
(use `--allow-missing` to override).

Aggressive "test the limits" build (~500k entries; also blocks social/messaging, and only
fits the single-app partition layout):

```bash
python3 tools/build_blocklist.py data/blocklist.bin \
  https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \
  https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt
```

## First-time setup

If the device can't join WiFi, or nothing has been configured yet, it starts an open
access point **`C3-AdBlock-XXXX`** with a captive portal:

1. Join it from a phone. The setup page opens automatically.
2. Pick your network and type its password.
3. **Choose a dashboard admin password** (8+ characters; the user name is `admin`).
4. Tap **Connect**. The device saves the settings, reboots, and joins your network.

| To… | Do this |
|---|---|
| Move to a new WiFi network | Dashboard → **Forget WiFi**. The admin password is kept; leave that field blank in the portal. |
| Recover a forgotten admin password | Hold **BOOT** while powering on. This clears WiFi *and* the admin password and opens the portal. |
| Fix the "No admin password set" banner | Same as above: hold BOOT at power-on and set a password. |

## Use it

Point a device's DNS at the C3's IP, or add it as a **secondary resolver** on your router.
To test:

```bash
dig @<c3-ip> doubleclick.net   # -> 0.0.0.0  (blocked)
dig @<c3-ip> github.com        # -> real IP  (forwarded)
```

## Over-the-air updates

The dashboard at **http://c3adblock.local** handles all of these (they require the admin
password):

- **Blocklist upload.** Drop a freshly built `blocklist.bin` into *Blocklist → Upload*.
- **Remote auto-update.** Set a URL and an interval (1–720 hours), and the device pulls a prebuilt
  `blocklist.bin` on that schedule. The [blocklist workflow](#ci--github-actions) rebuilds
  the default list **every Monday** and publishes it at a stable URL:
  `https://github.com/aravindnayani/esp32-network-adblocker/releases/download/blocklist/blocklist.bin`
  (a fork with Actions enabled publishes the same file under its own
  `…/<owner>/<repo>/releases/…` URL). The URL must be **https://**; the server's
  certificate is checked (see [Security](#security)).
- **Firmware.** Upload `.pio/build/c3/firmware.bin` under *Firmware → OTA update*. The
  device verifies the image and reboots into it. You can also push over WiFi:
  ```bash
  pio run -t upload --upload-port c3adblock.local --upload-protocol espota
  ```
  (The device prompts for the OTA password: `OTA_PASS`, or the admin password.)

**Blocklist swaps are checked before they go live.** An uploaded or downloaded list
replaces the current one only if it's complete (matches the declared size), made of whole
5-byte entries, and sorted. If the new list fits in flash next to the current one (the
default ~0.5 MB list does), the current list keeps blocking during the transfer and stays
if the new one is rejected. When both don't fit (roughly, once the two lists add up to
more than the 1.3 MB partition), the new list replaces the old one in place: blocking
pauses during the transfer, and a failed transfer leaves no blocklist until the next good
one. The status line and upload message say which happened.

**4 MB flash tradeoff:** firmware OTA needs *two* app slots, which leaves ~1.3 MB for the
blocklist (**~250k domains max**). The aggressive 537k list only fits a single-app
partition table (no firmware OTA). Choose in `partitions.csv`:

| Partition | Offset | Size |
|---|---|---|
| nvs | `0x9000` | 20 KB |
| otadata | `0xe000` | 8 KB |
| app0 / app1 | `0x10000` / `0x160000` | 1.3125 MB each |
| spiffs (LittleFS blocklist) | `0x2b0000` | 1.3125 MB |

## Configuration reference

| Setting | Where | Default | Notes |
|---|---|---|---|
| Upstream resolver | `-DUPSTREAM_IP=a,b,c,d` / `-DUPSTREAM_PORT` build flags | Quad9 `9.9.9.9:53` | Add to `build_flags` in `platformio.ini` |
| Fallback WiFi | `WIFI_SSID` / `WIFI_PASS` in `secrets.h` | placeholders (ignored) | Portal-saved WiFi takes priority |
| Admin user | `WEB_USER` in `secrets.h` | `admin` | |
| Admin password | Setup portal (NVS), else `WEB_PASS` | none, so the API is locked | Placeholder is ignored; minimum 8 chars in the portal |
| OTA password | `OTA_PASS` | falls back to the admin password | With no password, network OTA is off |
| Hash width | `HASH_BYTES` in `main.cpp` **and** `build_blocklist.py` | 5 (40-bit) | The two must match |
| DNS clients | `-DDNS_SUBNET_ONLY` build flag | own subnet + private ranges | With the flag: own subnet only. Other sources are dropped |
| Limits | `main.cpp` | 96 clients (when full, the least recently seen is replaced; bans are kept separately), 200 custom domains, 32 bans | |

## Security

The dashboard page (`/`) and a **summary** in `/stats.json` (totals, uptime, blocking on/off,
whether a password is set) are open to the LAN. Everything else in `/stats.json`, meaning
clients with their IPs and MACs, the custom list, the update URL and status, lockouts, pending
approvals and the audit log, is only included for a logged-in admin. The dashboard shows a
**Log in** button (`/login`) for it. Every state-changing endpoint requires
**HTTP Basic Auth** (user `admin` plus the admin password) **and** the
`X-Requested-With: c3-adblock` header **and** a valid `Host`:

- `/ban`, `/addblock`, `/unblock`, `/forgetwifi`, `/pause`, `/resume`
- `/upload`, `/update` (blocklist and firmware OTA)
- `/setupdate`, `/fetchnow`
- `/confirm`, `/setphys` (physical confirmation, below)

**Physical confirmation.** The checks above stop other devices and other web pages, but not
software acting *with* your credentials: an AI browser agent driving a tab where the dashboard
is logged in, a prompt injection, or anything that read the password off the LAN. So
`/update`, `/upload`, `/forgetwifi`, `/setupdate` with a changed URL, and `/pause` that is
indefinite or longer than 30 minutes also need a BOOT press. Shorter pauses only need the
password, and `/pause` accepts at most 24 hours.
The dashboard calls `/confirm?a=<action>` and the LED blinks. A press within 30 s approves that
action for the IP that asked, once, within 60 s. Without it they return `428`. Another IP can't
replace a pending request (`409`), and the dashboard shows which action and IP a press would
approve. Network OTA only runs for 60 s after a BOOT press with nothing pending. Turn it off
under **Security** (needs a press). Build flags: `-DCONFIRM_LED=<gpio>` / `-DCONFIRM_LED_ON=HIGH|LOW`,
or `-DCONFIRM_LED=-1` for no LED.

**Login lockout.** Five wrong passwords from one IP lock it out (`429` + `Retry-After`) for 30 s,
doubling per further failure up to 1 h; a correct password resets it. Requests with no
`Authorization` header (the browser's first try) don't count. On top of that, every wrong
password from any IP draws on one shared budget: a burst of about 20, refilling at one per
45 s. Once it's used up, every client gets `429` without a password check, so spreading
guesses over many LAN addresses gains nothing. Because that can lock the owner out too, a
BOOT press with nothing pending clears all lockouts (it's logged in the audit log).

**Audit log.** The last 32 admin events, with client IP/MAC, are on the dashboard once you
log in. It is in RAM only and is lost on reboot.

**No default passwords.** The placeholder values in `secrets.example.h` are public, so the
firmware ignores them. Until an admin password is set (in the portal, or as a real value
in `secrets.h`), every endpoint above returns 403 and the dashboard shows a banner. This
is why the prebuilt browser-flasher image is safe: it contains no credentials.

**Network OTA** (`ArduinoOTA`) requires `OTA_PASS`, or the admin password when `OTA_PASS`
is the placeholder. With no password at all, it isn't started.

**Basic Auth is a LAN-trust-boundary control, not encryption.** Everything is plain HTTP
on :80; this chip has no realistic budget for a TLS server. Credentials are base64 on
every authenticated request, so anyone who can already sniff your LAN (open/guest WiFi,
ARP spoofing) can read them. This protects against the common cases: another device
hitting the API without credentials, or a browser tab CSRF'ing it. It does not protect
against an on-path attacker.

**CSRF via cached Basic Auth.** Browsers attach cached Basic Auth credentials to *any*
later request to that origin, including one fired by an unrelated page
(`<img src="http://c3adblock.local/forgetwifi">`). The required custom header can only be
set by a same-origin `fetch()`, which is what the dashboard's own JS uses. This is also
why `/forgetwifi` isn't a URL you can visit directly; use the dashboard button.

**DNS rebinding.** A malicious page can point its own hostname at the device's LAN IP,
which makes its scripts "same-origin" and lets them get past the CSRF check. The browser
still sends the attacker's name in `Host`, so the dashboard only answers requests for
`c3adblock.local`, `c3adblock`, or the device's IP, and returns 403 otherwise. If you
reach the dashboard through another DNS name, use the IP instead.

**Verified blocklist downloads.** Remote updates are https-only, and the server
certificate (and hostname) is checked against a small built-in set of root CAs: Let's
Encrypt, Sectigo/USERTrust, DigiCert, Google Trust Services, GlobalSign, and Amazon. That
covers GitHub and most HTTPS hosts; the full Mozilla set doesn't fit next to two firmware
slots. Before this, anyone on the network path could serve the device a list that blocks
nothing, or one that blocks sites of their choosing. To trust another CA, add it to
`ROOTS` in `tools/gen_ca_bundle.py`, then run `pip install certifi` and
`python3 tools/gen_ca_bundle.py` to regenerate `src/ca_bundle.h`. Certificate dates
aren't checked, because the device has no clock.

**Not an open resolver.** DNS answers only clients on the device's own subnet or in a
private range (10/8, 172.16/12, 192.168/16, 100.64/10 CGNAT/Tailscale, 169.254/16), so
routed LAN segments like VLANs or a guest network still work. Queries from any other
address are dropped without a reply, and the dashboard counts them as "Dropped
(non-local)". Without this, a forwarded or UPnP-opened port 53 would make the device a
public resolver and an amplifier for spoofed-source attacks. A spoofed *private* source
can't be used that way, because the replies go to an address the internet can't reach.
For stricter control, build with `-DDNS_SUBNET_ONLY` to accept only the device's own
subnet. The dashboard on port 80 isn't filtered by address; it relies on the password
and Host checks above.

**XSS.** Custom domains, SSIDs, and WiFi names are HTML-escaped before rendering.

**Input validation.** Custom domains must be plain hostnames (letters, digits, `-`, `_`,
dot-separated labels of up to 63 characters, 253 total); `/addblock` returns `400` with the
reason otherwise. The update URL can't contain spaces or control characters, and every string
in `/stats.json` has control characters escaped, so nothing stored can break the dashboard.

**Out of scope:** the setup AP (`C3-AdBlock-XXXX`) is open by design, because it has to
be joinable before any password exists. The WiFi and admin passwords typed into the
portal are only as safe as that local radio link during the brief setup window.

## CI / GitHub Actions

| Workflow | Trigger | What it does |
|---|---|---|
| [`build.yml`](.github/workflows/build.yml) | push to `main`, PRs | Compiles firmware for `c3` and `esp32dev`; tests the blocklist tool (hosts / plain / AdGuard parsing + `tools/test_*.py` unit tests) |
| [`blocklist.yml`](.github/workflows/blocklist.yml) | Mondays 04:17 UTC, manual | Rebuilds the default blocklist, checks its size, and publishes it to the `blocklist` release |
| [`flasher.yml`](.github/workflows/flasher.yml) ✨ new | push to `main` touching firmware/docs, manual | Builds the browser-installer images from source with placeholder secrets, checks the auth code and flash offsets, and deploys to GitHub Pages |

## Project layout

```
src/main.cpp              firmware: DNS sinkhole, lookup, dashboard API, portal, OTA
src/page.h                dashboard HTML/JS (PROGMEM)
src/secrets.example.h     optional fallback WiFi / passwords → copy to secrets.h
tools/build_blocklist.py  hosts/domains/AdGuard lists → sorted 40-bit hash blob
tools/test_*.py           unit tests for the blocklist builder
data/                     LittleFS image contents (blocklist.bin goes here)
docs/                     ESP Web Tools installer page + manifest (CI-built images)
hardware/                 printable C3 SuperMini enclosure (STL)
partitions.csv            dual-OTA 4 MB layout
platformio.ini            envs: c3 (default), esp32dev
LICENSE                   GPL-3.0 (this project)
LICENSE-UPSTREAM-MIT      MIT notice for code from M-Abozaid/esp32-c3-adblock
```

## Gotchas

- **ModemManager** (default on Fedora/Ubuntu) grabs `/dev/ttyACM0` and toggles DTR/RTS,
  which **resets the C3** and blocks serial. Fix:
  ```bash
  sudo systemctl stop ModemManager
  echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
  sudo udevadm control --reload-rules && sudo udevadm trigger
  ```
- The C3's USB-Serial-JTAG console can swallow early boot output until the host
  connects (`while(!Serial)` helps).
- DNS clients add an **EDNS OPT** record. A blocked reply must contain only the
  question and answer (ANCOUNT=1, NSCOUNT=ARCOUNT=0), or it's malformed.
- Getting a `403 bad Host header`? You reached the device through a name other than
  `c3adblock.local`; use its IP.

## Roadmap

- ✅ Web dashboard: per-client counts, ban a client, custom domains, pause blocking
- ✅ mDNS (`c3adblock.local`)
- ✅ OTA: firmware + blocklist over WiFi, plus scheduled remote blocklist pulls
- ✅ Captive-portal WiFi setup + one-click browser installer
- ✅ RAM first-level index + lookup cache (one flash read per lookup)
- ✅ Admin password set on the device; no default credentials; DNS-rebinding guard
- ✅ CI-built, credential-free browser-flasher images
- ✅ Installer page (`docs/index.html`) walks through choosing the admin password
- ✅ BOOT-button confirmation for risky actions, login lockout, audit log
- ⬜ Act as the DHCP server (hand itself out as DNS) for true plug-and-play

## Inspiration & Thanks

This project exists because of other people's work. Thank you to:

- **[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)** by
  Zed (M-Abozaid). This is the upstream project: the hash-in-flash design, firmware,
  dashboard, captive portal, OTA, blocklist tooling, enclosure, and nearly everything
  else here.
- **[s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker)**, which inspired
  the upstream project with the original "answer 0.0.0.0 for blocklisted domains on an
  ESP32" idea.
- **[Pi-hole](https://pi-hole.net/)**, the model for a network-wide DNS sinkhole, and
  where the "pause blocking for a while" UX comes from.
- **Upstream contributors:**
  - **ThousanDIY / tomorrow56**: classic ESP32 (DevKit) build target and the
    Japanese README in the upstream project.
  - **L4Ph**: the RAM first-level index + lookup cache that made lookups a single flash read.
  - **cesar-xyz**: authentication + CSRF on the control/OTA endpoints and the stored-XSS
    fix, which this fork builds on.
  - **Александр М.**: HTML-escaping of SSIDs/WiFi names in the setup portal (#24).
  - **Rahul**: hosts-file parsing fix to include every domain on a line (#23).
- **Blocklist maintainers:** [StevenBlack/hosts](https://github.com/StevenBlack/hosts) and
  [Hagezi's DNS blocklists](https://github.com/hagezi/dns-blocklists). They provide the
  default list.
- **[ESP Web Tools](https://esphome.github.io/esp-web-tools/)** (ESPHome) for the
  browser installer.
- **[PlatformIO](https://platformio.org/)**, **[Arduino-ESP32](https://github.com/espressif/arduino-esp32)**,
  and **Espressif** for the toolchain, framework, and $2 silicon.
- **[Quad9](https://quad9.net/)** for the default upstream resolver.
- The **FNV-1a** hash by Glenn Fowler, Landon Curt Noll, and Kiem-Phong Vo.
- **Tom's Hardware, XDA Developers, and Korben** for covering the project, and everyone
  who filed issues and tested on their own boards.

## License

GPL-3.0. See [LICENSE](LICENSE).

This project builds on [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock),
which is MIT-licensed. The code that came from upstream stays under the MIT License; its
copyright and permission notice are kept in [LICENSE-UPSTREAM-MIT](LICENSE-UPSTREAM-MIT).
