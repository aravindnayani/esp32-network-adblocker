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

**You need:** one of the boards below, a USB cable, and a computer with Chrome, Edge, Safari or Firefox.

| Board | Price | Blocklist room | Prebuilt image |
|---|---|---|---|
| **ESP32-C3**, 4 MB flash (e.g. C3 SuperMini) — *recommended* | ~$2 | ~250k domains | ✅ |
| **ESP32-S3**, 8 MB+ flash (e.g. S3 DevKitC-1 N8/N16) | ~$5–10 | ~1M domains | ✅ |
| Classic **ESP32**, 4 MB (DevKit / WROOM) | ~$3–5 | ~250k domains | build from source |

The C3 is plenty for the default ~100k-domain list. Pick the S3 if you want very large lists (it fits the ~500k "everything" list and still updates over WiFi).

### ▶ Open [`START-HERE.html`](START-HERE.html)

Clone or download this repository and open **`START-HERE.html`** in your browser. Pick your board, install method, computer and browser, and it shows exactly the steps you need, from flashing to the dashboard, with commands you can copy:

```bash
git clone https://github.com/aravindnayani/esp32-network-adblocker
open esp32-network-adblocker/START-HERE.html     # Windows: start …, Linux: xdg-open …
```

Chrome and Edge flash straight from the [web installer](https://aravindnayani.github.io/esp32-network-adblocker/). Safari and Firefox can't talk to USB devices, so the page walks you through three `esptool` commands instead. It works offline, and nothing you type into it leaves the page.

### Turn it on for your network

Set your router's DNS server to the ESP32's IP address. You can also set it on a single device first to try it out.

Check that it's working:

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
| Block one more site | Add it under **Custom domains** |
| Cut off a device | **Ban** it. The ban follows its MAC address, so changing its IP won't help. |
| Keep the blocklist fresh | Set an **auto-update URL**, e.g. the weekly build below |
| Update the firmware | **Firmware → OTA update**, then press BOOT when the LED blinks |
| Move to a new WiFi | **Forget WiFi**. Your admin password is kept. |
| Recover a lost password | Hold **BOOT** while plugging it in. This wipes WiFi and the password and reopens setup. |

**Weekly blocklist:** a fresh default list is published every Monday at
`https://github.com/aravindnayani/esp32-network-adblocker/releases/download/blocklist/blocklist.bin`

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

Choose **Build from source** in [`START-HERE.html`](START-HERE.html): it fills in `src/secrets.h` for you and gives the PlatformIO commands for your board. In short:

```bash
pip install -U platformio
cp src/secrets.example.h src/secrets.h           # every value in it is optional
python3 tools/build_blocklist.py data/blocklist.bin
pio run -t upload && pio run -t uploadfs
```

After that, firmware and blocklists update over WiFi.

→ Custom blocklists, settings, partition layout and troubleshooting: [guide/building.md](guide/building.md)

---

## Hardware tips

- **Board:** see the [table above](#get-started). The C3 is the main tested target. The classic ESP32 is community-contributed and compile-tested.
- **BOOT LED:** blinks when an action waits for your press. It's the blue LED on a C3 SuperMini and the RGB LED on an S3 DevKitC-1. On a DevKitC-1 v1.1 the RGB LED moved to GPIO 38, so build with `-DCONFIRM_LED=38 -DCONFIRM_LED_RGB`.
- **Power:** use a solid USB source. A router's USB port plus a USB-A→C adapter works well. Cheap adapters can cause dropouts.
- **Case:** a printable C3 SuperMini enclosure is in [`hardware/`](hardware/esp32-c3-supermini-enclosure.stl). Keep the antenna end (opposite the USB port) clear of plastic and metal.

---

## Credits

Built on **[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)** by Zed. The hash-in-flash idea, the original firmware, and the dashboard come from there. This fork adds the security hardening, encrypted upstream DNS, BOOT-button approvals and CI-built installer.

Thanks also to [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker), [Pi-hole](https://pi-hole.net/), the upstream contributors (ThousanDIY, L4Ph, cesar-xyz, Александр М., Rahul), the [StevenBlack](https://github.com/StevenBlack/hosts) and [Hagezi](https://github.com/hagezi/dns-blocklists) blocklists, [ESP Web Tools](https://esphome.github.io/esp-web-tools/), PlatformIO, Espressif, and [Quad9](https://quad9.net/).

## License

GPL-3.0 ([LICENSE](LICENSE)). Code from upstream stays MIT ([LICENSE-UPSTREAM-MIT](LICENSE-UPSTREAM-MIT)).
