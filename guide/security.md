# Security model

[← Back to README](../README.md)

The goal: a credential-free image anyone can flash from a browser, which then can't be quietly taken over by another device, a malicious web page, or software running in your own logged-in browser.

## Layer by layer

| Threat | Defence |
|---|---|
| Someone sniffing the LAN | Dashboard is HTTPS only. Port 80 just redirects. |
| Default or leaked passwords | There are none. The placeholders in `secrets.example.h` are ignored. With no admin password set, every control endpoint returns `403`. |
| A random web page firing requests at the device | A custom `X-Requested-With: c3-adblock` header is required. Only the dashboard's own JavaScript can send it. |
| DNS rebinding | Only `c3adblock.local`, `c3adblock` or the device IP are accepted as `Host`. Anything else gets `403`. |
| Password guessing | Per-IP lockout plus a network-wide budget |
| Malware or an AI agent using your password | Risky actions need the physical BOOT button |
| Tampered blocklist downloads | https only, with the certificate and hostname checked |
| The internet using it as a DNS amplifier | Answers only local and private addresses |
| Someone reading flash | Passwords are stored salted and hashed (see the caveats below) |

## What needs a login

Anyone on the LAN can see the dashboard and a **summary** of `/stats.json` (totals, uptime, whether blocking is on, whether a password is set). Everything else needs a login: client IPs and MACs, the custom list, the exceptions, the update URL, lockouts, pending approvals and the audit log. Use the **Log in** button (`/login`).

These endpoints need Basic Auth (`admin` + password) **and** the custom header **and** a valid `Host`:

`/ban` `/addblock` `/unblock` `/allow` `/unallow` `/forgetwifi` `/pause` `/resume` `/upload` `/update` `/setupdate` `/fetchnow` `/confirm` `/setphys`

## BOOT-button approvals

A password proves *who* is asking, but not that a *human* is asking. An AI browser agent in your logged-in tab, a prompt-injected script, or anyone who sniffed the password could otherwise do anything you can.

These actions also need a BOOT press:
- firmware upload (`/update`)
- blocklist upload (`/upload`)
- setting a **new** auto-update URL (`/setupdate`)
- **Forget WiFi**
- pausing longer than the free budget (below)

**How it works:**
1. The dashboard calls `/confirm?a=<action>&p=<param>`, and the LED starts blinking.
2. Press BOOT within **30 s**.
3. That press approves **one** request, from **that IP**, with **that exact parameter**, within **60 s**. Without a press, the request gets `428`.

The parameter is pinned down per action:

| Action | What gets approved |
|---|---|
| `setupdate` | the exact URL |
| `pause` | the length in seconds (`0` = forever) |
| `upload`, `update` | `<size>:<fnv32 hex>` of the file. The device hashes the file as it arrives and rejects a mismatch before it's saved or flashed. |

Picking categories under **What to block** is a new auto-update URL (one of this project's weekly lists), so it needs a press too. Adding an **exception** (a domain that's never blocked) needs only the password, like adding a custom blocked domain. Every change to either list is in the audit log.

A pending request can't be replaced, even from the same IP (`409`). It has to be cancelled with `/confirm?cancel=1`, and the cancel is logged. The dashboard shows what a press would approve. A browser agent could fake what that tab shows, though, so if something looks wrong, check the audit log from another device.

**Pause budget.** Up to 15 minutes of pausing per hour needs only the password. Anything longer needs a press, and pauses are capped at 7 days. Resuming early doesn't give the unused time back. This stops software from switching blocking off for good, either with one call or by re-pausing every few minutes.

**Network OTA** (`espota`) only listens for 60 s after a BOOT press made while nothing is pending.

You can turn approvals off under **Security** on the dashboard (that also needs a press). Holding BOOT at power-on turns them back on.

## Login lockout

- **Per IP:** after 5 wrong passwords, that IP gets `429` + `Retry-After` for 30 s. The lockout doubles with each further failure, up to 1 h. A correct password resets it. A first try with no credentials doesn't count.
- **Network-wide:** all wrong passwords share one budget, a burst of ~20 that refills at one per 45 s. Once it's empty, everyone gets `429`, so spreading guesses across many IPs gains nothing.
- **Unlock:** press BOOT (with nothing pending) to clear every lockout. The unlock is logged.

## Audit log

The last 32 admin events are kept: actions, wrong passwords, lockouts, approvals and BOOT presses, each with time, IP and MAC. You see them on the dashboard once you're logged in. The log is RAM only, so it's lost on reboot.

## HTTPS details

On first boot the device creates an ECDSA P-256 key and a self-signed certificate and saves them in NVS. The fingerprint stays the same across reboots, updates and BOOT resets. Accept the browser warning once, after checking that the fingerprint matches the setup page or the serial console. After that, an on-path attacker can't swap certificates without triggering a new warning.

Inside the device, a small TLS front end passes each request to the web server, which listens only on loopback. It forwards the real client address along with a per-boot secret, so lockouts and approvals still see the real client.

## Why the custom header (CSRF)

Browsers re-send cached Basic Auth to *any* request to that origin, including one triggered by another site, e.g. `<img src="https://c3adblock.local/forgetwifi">`. A custom header can only be set by a same-origin `fetch()`, which is why `/forgetwifi` can't be opened as a plain link.

## Why the Host check (DNS rebinding)

A malicious site can point its own domain at your device's IP. Its scripts then count as "same-origin" and could send the custom header. The browser still sends the attacker's domain in `Host`, though, so the device rejects the request. If you reach the dashboard through some other DNS name, use the IP instead.

## Verified blocklist downloads

Remote blocklist URLs must be **https://**. The server's certificate and hostname are checked against a small built-in set of roots: Let's Encrypt, Sectigo/USERTrust, DigiCert, Google Trust Services, GlobalSign and Amazon. That covers GitHub, Quad9 and most hosts. The full Mozilla bundle (~63 KB) would trust far more CAs than needed. Certificate dates aren't checked, because the device has no clock. To add a CA, see [building.md](building.md#settings).

## Not an open resolver

DNS answers only come from the device's own subnet or private ranges: 10/8, 172.16/12, 192.168/16, 100.64/10 (CGNAT/Tailscale) and 169.254/16. VLANs and guest networks therefore still work. Queries from anything else are dropped silently and counted as "Dropped (non-local)". Without this, an exposed port 53 could be used to amplify attacks. Build with `-DDNS_SUBNET_ONLY` to allow only the device's own subnet.

## Input handling

- Custom domains and exceptions must be plain hostnames (labels up to 63 chars, 253 total). Anything else gets `400` with the reason.
- The update URL can't contain spaces or control characters.
- Every string in `/stats.json` is escaped, and SSIDs and domains are HTML-escaped before they're displayed.
- Upload auth flags are reset after every request, so one upload can't authorize the next.

## What's stored on the device

| Secret | How it's stored |
|---|---|
| Admin password | random salt + PBKDF2-HMAC-SHA256 (10,000 rounds). Firmware from before this change stored it in plain text; it's converted on first boot. |
| OTA password | MD5 of the password, because espota's protocol requires it. It is **unsalted and fast to crack**, so use a long admin password or set a separate `OTA_PASS`. |
| WiFi (WPA/WPA2) | the derived key (PMK), not your passphrase, once it has connected |
| WiFi (WPA3-only) | the passphrase, because WPA3 needs it |
| Values in `secrets.h` | compiled into the firmware as written |

Only **flash encryption** fully protects these from someone holding the device. It's off because it permanently burns eFuses and the browser installer can't set it up. If you build from source and want it, see Espressif's flash-encryption guide.

## Setup over USB

`start-here.py` sets the device up over its USB cable instead of the setup WiFi. In setup mode the firmware accepts three line commands on the USB console:

| Command | Answer |
|---|---|
| `INFO` | mode (setup/online), IP, setup WiFi name, certificate fingerprint, whether an admin password is set |
| `NETS` | the WiFi networks it scanned, hex-encoded (setup mode only) |
| `PROVISION <ssid> <pass> <admin> [<current>]` | saves WiFi + admin password and restarts (setup mode only); fields are hex-encoded UTF-8 |

`PROVISION` follows the setup page's rules exactly: a device that already has an admin password needs the current one unless BOOT was held at power-on, wrong guesses count towards the same 5-try limit, and it's refused once the device is online. This gives nothing away: whoever holds the USB cable can already reflash the chip or read the setup WiFi password the console prints.

The helper itself listens on `127.0.0.1` only, answers only requests whose `Host` is `127.0.0.1` or `localhost` on its port (no DNS rebinding), and requires a random per-run token on every API call. The token is only in the page it serves, and the API sends no CORS headers, so other web pages can't read the token or call the API. Passwords go from the page to the device and are never written to disk or logged.

## Setup network

The setup WiFi `C3-AdBlock-XXXX` is WPA2 with a random password. The password is created on first boot, never changes, and is shown only on the serial console (at boot and every 15 s while setup is running). The setup page is plain HTTP, but it's inside that encrypted WiFi link.

## Recovery

Hold **BOOT** while powering on. This clears the saved WiFi **and** the admin password and always opens the setup portal, even if `secrets.h` has fallback WiFi. Physical access is the recovery key.
