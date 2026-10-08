# Building, configuring and troubleshooting

[← Back to README](../README.md)

## Build and flash

You only flash over USB once. After that, firmware and blocklists update over WiFi.

```bash
cp src/secrets.example.h src/secrets.h              # optional fallback WiFi and passwords
python3 tools/build_blocklist.py data/blocklist.bin # default: StevenBlack + Hagezi Light
pio run -t upload                                   # firmware
pio run -t uploadfs                                 # blocklist
pio device monitor                                  # shows setup password, cert fingerprint, IP
```

For a classic ESP32, add `-e esp32dev` to every `pio` command.

> **Use a recent PlatformIO.** The distro/apt package (e.g. 4.3.4) is too old and fails with `AttributeError: ... 'resultcallback'`. Install it with `pip install -U platformio` in a venv, or use the VS Code extension.
>
> To match CI exactly, install the pinned version: `pip install --require-hashes -r tools/requirements-ci.txt`.

## Custom blocklists

```bash
python3 tools/build_blocklist.py OUT.bin [SOURCE ...]
```

Sources can be URLs or local files, in any mix of these formats:

| Format | Example |
|---|---|
| hosts file | `0.0.0.0 ads.example.com tracker.example.com` |
| plain list | `ads.example.com` (one per line) |
| AdGuard / Adblock | `\|\|ads.example.com^` to block, `@@\|\|ok.example.com^` to unblock |

Good to know:
- Rules a hash list can't represent (regex, wildcards, `$` modifiers, `##` cosmetic rules) are skipped and counted.
- `@@` only removes that exact entry. It can't unblock one subdomain of a blocked parent.
- If a source fails to download, the build stops. Pass `--allow-missing` to continue anyway.

**The "everything" list (~500k entries).** This also blocks social and messaging apps, and it only fits the single-app partition layout:

```bash
python3 tools/build_blocklist.py data/blocklist.bin \
  https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \
  https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt
```

## Updating over WiFi

| What | How |
|---|---|
| Blocklist, one-off | Dashboard → *Blocklist → Upload* a `blocklist.bin` |
| Blocklist, scheduled | Dashboard → set an https URL and an interval (1–720 h) |
| Firmware, browser | Dashboard → *Firmware → OTA update* with `.pio/build/c3/firmware.bin` |
| Firmware, command line | `pio run -t upload --upload-port c3adblock.local --upload-protocol espota` |

Uploads, new URLs and firmware all need a BOOT press (see [security.md](security.md)). `espota` asks for `OTA_PASS`, or the admin password if `OTA_PASS` isn't set.

**A new blocklist must pass checks before it's used.** It must reach its declared size, be made of whole 5-byte entries, and be sorted.
- If both lists fit in flash at once (the default list does), the old list keeps blocking during the transfer and stays if the new one is rejected.
- If they don't fit together, the new list overwrites the old one. Blocking pauses during the transfer, and a failed transfer leaves no list until the next good one.

The dashboard tells you which of these happened.

## Settings

| Setting | Where | Default |
|---|---|---|
| Upstream resolver | build flags `-DUPSTREAM_IP=a,b,c,d`, `-DUPSTREAM_DOT_HOST='"name"'`, `-DUPSTREAM_DOT_PORT` | Quad9 `9.9.9.9`, DoT to `dns.quad9.net:853` |
| Plain-UDP upstream | `-DUPSTREAM_PLAIN` (+ `-DUPSTREAM_PORT`, default 53) | off |
| Fallback WiFi | `WIFI_SSID` / `WIFI_PASS` in `secrets.h` | none. WiFi saved in the portal wins. |
| Admin user | `WEB_USER` in `secrets.h` | `admin` |
| Admin password | setup portal, else `WEB_PASS` | none, so everything stays locked |
| OTA password | `OTA_PASS` | the admin password |
| Who may use DNS | `-DDNS_SUBNET_ONLY` | own subnet + private ranges |
| BOOT LED | `-DCONFIRM_LED=<gpio>`, `-DCONFIRM_LED_ON=HIGH\|LOW`, `-1` for none | GPIO 8 (C3), GPIO 2 (esp32dev) |
| Hash width | `HASH_BYTES` in `main.cpp` **and** `build_blocklist.py` | 5. The two must match. |
| Limits | `main.cpp` | 96 clients, 200 custom domains, 32 bans |

A custom upstream host must match its certificate, and that certificate's root CA must be in `src/ca_bundle.h`. To add a CA, edit `ROOTS` in `tools/gen_ca_bundle.py`, then run `pip install certifi && python3 tools/gen_ca_bundle.py`.

## Partition layout (4 MB)

| Partition | Offset | Size |
|---|---|---|
| nvs | `0x9000` | 20 KB |
| otadata | `0xe000` | 8 KB |
| app0 / app1 | `0x10000` / `0x160000` | 1.3125 MB each |
| spiffs (blocklist) | `0x2b0000` | 1.3125 MB |

## CI

| Workflow | When | What |
|---|---|---|
| [`build.yml`](../.github/workflows/build.yml) | push to `main`, PRs | Builds `c3` + `esp32dev`, tests the blocklist tool |
| [`blocklist.yml`](../.github/workflows/blocklist.yml) | Mondays 04:17 UTC | Rebuilds the default list and publishes it to the `blocklist` release |
| [`flasher.yml`](../.github/workflows/flasher.yml) | push to `main` | Builds credential-free installer images, checks them, and deploys to GitHub Pages |

For a fork, enable Pages once: **Settings → Pages → Source: GitHub Actions**.

## Project layout

```
src/main.cpp              firmware: DNS, lookup, dashboard API, portal, OTA
src/page.h                dashboard HTML/JS
src/secrets.example.h     optional settings template, copy to secrets.h
src/ca_bundle.h           trusted root CAs (generated)
tools/build_blocklist.py  domain lists → sorted 40-bit hash file
tools/gen_ca_bundle.py    regenerates ca_bundle.h
tools/test_*.py           tests for the blocklist builder
data/                     filesystem image (blocklist.bin)
docs/                     browser installer page (GitHub Pages)
hardware/                 printable enclosure
```

## Troubleshooting

**The board keeps resetting or the serial port is busy on Linux.** ModemManager is grabbing the port. Fix it with:
```bash
sudo systemctl stop ModemManager
echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

**Early boot messages are missing.** The C3's USB console can drop output until your computer connects. Just reconnect the monitor.

**`403 bad Host header`.** You reached the dashboard through some other name. Use `c3adblock.local` or the IP.

**Random dropouts.** These are usually caused by power. Try a better USB supply.

**Writing your own DNS code?** Clients add an EDNS OPT record. A blocked reply must contain only the question and one answer (ANCOUNT=1, NSCOUNT=ARCOUNT=0), or clients treat it as malformed.
