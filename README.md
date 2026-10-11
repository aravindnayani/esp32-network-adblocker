# esp32-network-adblocker

**Block ads and trackers for your whole home network with a $2 ESP32-C3 plugged into your router's USB port.**

It works like a pocket Pi-hole: every device on your network asks it for website addresses, and it answers "nowhere" for over 100,000 known ad and tracking domains. Everything else gets looked up for real, encrypted.

```
your phone ──"where is ads.example.com?"──▶  ESP32  ──▶  0.0.0.0   (blocked)
your laptop ─"where is github.com?"───────▶  ESP32  ──▶  Quad9 over TLS ──▶ real answer
```

## Why it's different

- **No Raspberry Pi, no PSRAM.** The whole blocklist lives in flash as tiny hashes, so the chip needs only ~50 KB of RAM.
- **No passwords baked in.** The prebuilt image ships empty. You set the WiFi and admin password on the device itself.
- **Your lookups stay private.** Allowed queries go to Quad9 over DNS-over-TLS. If encryption fails, lookups fail. They never fall back to plain text.
- **Software can't take it over on its own.** Risky actions like new firmware, a new blocklist or a long pause need a press of the physical **BOOT** button, not just the password.

---

## Get started

**You need:** one of the boards below, a USB cable, and a computer with Python 3.9+ and Chrome, Edge, Safari or Firefox.

| Board | Price | Blocklist room | Prebuilt image |
|---|---|---|---|
| **ESP32-C3**, 4 MB flash (e.g. C3 SuperMini) — *recommended* | ~$2 | ~250k domains | ✅ |
| **ESP32-S3**, 8 MB+ flash (e.g. S3 DevKitC-1 N8/N16) | ~$5–10 | ~1M domains | ✅ |
| Classic **ESP32**, 4 MB (DevKit / WROOM) — *tight on RAM, see [below](#classic-esp32)* | ~$3–5 | ~250k domains | build from source |

The C3 is plenty for the default ~100k-domain list, and for every category combination the dashboard offers (at most ~180k). Pick the S3 if you want very large lists (it fits the ~500k "everything" list and still updates over WiFi). If you're buying a board, get a C3 or an S3 rather than a classic ESP32.

### ▶ Run the setup helper

Get this repository, then start the helper from its folder:

```bash
git clone https://github.com/aravindnayani/esp32-network-adblocker
cd esp32-network-adblocker
python3 start-here.py          # Windows: py start-here.py
```

It opens a setup page in your browser (Chrome, Edge, Safari or Firefox) and does the rest from there. It checks your computer, finds the board on USB, flashes it, and sends your WiFi and admin password to it over the cable. No setup WiFi, no terminal commands to copy. You only need Python 3.9+; the helper puts esptool in a private `.setup-venv` folder.

New to the terminal? Open [`START-HERE.html`](START-HERE.html) in your browser first. It shows how to install Python and start the helper on macOS, Windows or Linux.

Once the board is online, open **https://c3adblock.local** (or its IP, which the setup page shows). Its **Finish setting up** card walks you through choosing what to block (social media, gambling, adult content, fake news, on top of ads and trackers), exceptions for apps that must keep working, and pointing your router at it.

Keep the board plugged into your computer until you've done that: it's already on your WiFi, and the helper can show what it prints if anything goes wrong. Then stop the helper (Ctrl+C), and move the board to your router's USB port or any USB charger near it. It keeps its settings and rejoins WiFi by itself.

The board needs **2.4 GHz** WiFi. On a mixed WPA2/WPA3 network it joins with WPA2, which those networks accept by design (the classic ESP32 lost broadcast traffic on WPA3).

### Turn it on for your network

The dashboard tells you how, and ticks it off once devices start using it: set your router's DNS server to the ESP32's IP address. You can also set it on a single device first to try it out.

To check from a terminal:

```bash
dig @<esp32-ip> doubleclick.net
```

You should get back `0.0.0.0`.

---

## Everyday use

All of this happens on the dashboard at **https://c3adblock.local** (user `admin`).

| You want to… | Do this |
|---|---|
| See what's being blocked | Dashboard home: blocked and allowed counts for each device |
| Turn blocking off for a bit | **Pause**. Up to 15 min/hour needs only the password. Longer needs a BOOT press. |
| Choose what to block | **What to block**: ads & trackers always, plus social media, gambling, adult content, fake news. Needs a BOOT press. |
| Keep an app working anyway | Add an **exception**, or a quick pick like WhatsApp or YouTube. It covers subdomains too. |
| Block one more site | Add it under **Custom domains** |
| Cut off a device | **Ban** it. The ban follows its MAC address, so changing its IP won't help. |
| Keep the blocklist fresh | Automatic after **What to block**. Or set your own **auto-update URL**. |
| Update the firmware | **Firmware → OTA update**, then press BOOT when the LED blinks |
| Move to a new WiFi | **Forget WiFi**, then run `start-here.py` again. Your admin password is kept. |
| Recover a lost password | Hold **BOOT** while plugging it in, then run `start-here.py` again. This wipes WiFi and the password. |

**Weekly blocklists:** fresh lists are published every Monday: `blocklist.bin` (ads and trackers) and `blocklist-<categories>.bin` for each combination of categories, at
`https://github.com/aravindnayani/esp32-network-adblocker/releases/download/blocklist/`

---

## How a $2 chip holds a quarter-million domains

Most ESP32 ad-blockers keep the domain names in RAM, so they need a pricier board with PSRAM. This one turns each domain into a **5-byte fingerprint** (a 40-bit FNV-1a hash), sorts the fingerprints, and leaves them in flash.

| | Names in RAM | Fingerprints in flash (this) |
|---|---|---|
| Board | ESP32 + PSRAM, ~$8 | ESP32-C3, ~$2 |
| Space for 141k domains | ~2.5 MB RAM | **0.67 MB flash** |
| Lookup | string search in RAM | ~10 ms, one flash read |

A small index in RAM points each lookup to a single flash read. Blocking `example.com` also blocks every subdomain under it.

→ More detail, including why 40 bits is the right size: [guide/how-it-works.md](guide/how-it-works.md)

---

## Security at a glance

- Dashboard is **HTTPS only**, with a certificate the device generates on first boot.
- Changing anything needs the **admin password**, plus checks against cross-site requests and DNS-rebinding attacks.
- **Wrong passwords lock you out**, per IP and across the whole network.
- Risky actions need the **BOOT button**. Each press approves one exact request.
- An **audit log** of the last 32 admin events is on the dashboard.
- It only answers DNS for **local devices**, so it can't be abused as an open resolver.
- Passwords are stored **salted and hashed**, never in plain text.

→ The full threat model and every endpoint: [guide/security.md](guide/security.md)

---

## Building it yourself

Choose **Build from source** in the setup helper (`python3 start-here.py`): it installs PlatformIO into `.setup-venv`, builds for your board and flashes it. By hand:

```bash
pip install -U platformio
cp src/secrets.example.h src/secrets.h           # every value in it is optional
python3 tools/build_blocklist.py data/blocklist.bin
pio run -t upload && pio run -t uploadfs
```

After that, firmware and blocklists update over WiFi.

- **On an Apple Silicon Mac, install Rosetta 2 first** (`softwareupdate --install-rosetta --agree-to-license`). Two of the pinned PlatformIO tools, the C3 compiler and `mklittlefs`, only ship Intel binaries. The helper checks for it before building. The prebuilt images need nothing extra.
- **Flashing from source resets the dashboard's settings.** `uploadfs` (and the helper's *Build from source*) rewrites the whole filesystem: what to block, the auto-update URL, exceptions, custom domains and bans. WiFi and the admin password live elsewhere and are kept. Update firmware over WiFi (**Firmware → OTA update**) to keep them.

→ Custom blocklists, settings, partition layout and troubleshooting: [guide/building.md](guide/building.md)

---

## Hardware tips

- **Board:** see the [table above](#get-started). The C3 is the main tested target; the S3 is built and checked by CI the same way.
- **BOOT LED:** blinks when an action waits for your press. It's the blue LED on a C3 SuperMini and the RGB LED on an S3 DevKitC-1. On a DevKitC-1 v1.1 the RGB LED moved to GPIO 38, so build with `-DCONFIRM_LED=38 -DCONFIRM_LED_RGB`.
- **Power:** use a solid USB source. A router's USB port plus a USB-A→C adapter works well. Cheap adapters can cause dropouts.
- **Case:** a printable C3 SuperMini enclosure is in [`hardware/`](hardware/esp32-c3-supermini-enclosure.stl). Keep the antenna end (opposite the USB port) clear of plastic and metal.

### Classic ESP32

It works, but with little room to spare. On a classic ESP32 (WROOM, ESP32-D0WD-V3, no PSRAM), the device keeps two TLS sessions open, one for the dashboard and one for DNS-over-TLS, at about 33 KB each. That leaves about 75 KB free, with a largest block of about 29 KB. To make that hold up, the firmware:

- sends the dashboard page straight from flash
- reuses one TLS context instead of setting one up per request
- keeps the browser's connection open between refreshes
- prefers X25519 for the key exchange (a full handshake takes ~1.2 s, a resumed one well under 0.1 s)
- uses a smaller lookup index

Known limits:
- **Downloading a blocklist from the dashboard** (**What to block → Apply**, **Fetch now**, the daily auto-update) **still fails here** with `SSL - Memory allocation failed`. A third TLS session doesn't fit, even with DNS-over-TLS lending its memory for the download. Until that's fixed, build a list with `tools/build_blocklist.py` and use **Blocklist → Upload** on the dashboard.
- **One browser tab at a time is smoothest.** The device serves one HTTPS connection at a time and gives way when another is waiting, so two open dashboards take turns.
- **Uploads can hit serial noise.** The board's CP2102 USB-serial chip sometimes drops out at 460,800 baud ("The chip stopped responding"). Run *Install* again.

### When something goes wrong

The setup helper's **Board console** panel shows everything the board prints over USB, and can send it these commands:

| Command | What it does |
|---|---|
| `INFO` | Mode (setup or online), IP, setup WiFi name, certificate fingerprint, free memory |
| `NETS` | The WiFi networks the board can see (setup mode) |
| `DIAG` / `DIAG off` | A `[health]` line every 2 s. It shows free and lowest memory, the largest free block, whether the main loop and DNS task are running, what the HTTPS relay is doing, WiFi signal and free task stack. The board also prints one by itself when something looks stuck or memory runs low. |
| `FETCH [https-url]` | Download a blocklist now: the saved update URL, or the given one once, without saving it |

Each helper step's full log is also saved in `.setup-cache/logs/`.

---

## Credits

Built on **[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)** by Zed. The hash-in-flash idea, the original firmware, and the dashboard come from there. This fork adds the security hardening, encrypted upstream DNS, BOOT-button approvals and CI-built installer.

Thanks also to [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker), [Pi-hole](https://pi-hole.net/), the upstream contributors (ThousanDIY, L4Ph, cesar-xyz, Александр М., Rahul), the [StevenBlack](https://github.com/StevenBlack/hosts) and [Hagezi](https://github.com/hagezi/dns-blocklists) blocklists, [ESP Web Tools](https://esphome.github.io/esp-web-tools/), PlatformIO, Espressif, and [Quad9](https://quad9.net/).

## License

GPL-3.0 ([LICENSE](LICENSE)). Code from upstream stays MIT ([LICENSE-UPSTREAM-MIT](LICENSE-UPSTREAM-MIT)).
