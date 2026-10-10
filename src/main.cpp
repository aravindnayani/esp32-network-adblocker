// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/sockets.h"
#include "esp_wifi.h"           // AP auth mode, for storing a derived WiFi key
#include "mbedtls/md.h"         // password hashing (PBKDF2), SHA-256
#include "mbedtls/pkcs5.h"
#include "mbedtls/base64.h"
#include <MD5Builder.h>         // espota's password hash
#include "mbedtls/ssl.h"        // HTTPS front end for the dashboard
#include "mbedtls/ssl_cache.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/oid.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"        // mbedtls_strerror, for TLS failure notes
#include "esp_heap_caps.h"
#include "ca_bundle.h"  // trusted roots for HTTPS blocklist downloads (tools/gen_ca_bundle.py)
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- config ----
#ifndef UPSTREAM_IP
#define UPSTREAM_IP 9, 9, 9, 9                    // Quad9
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
static const IPAddress UPSTREAM(UPSTREAM_IP);
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
// First-level flash index. A lookup reads at most MAX_RANGE hashes from one bucket, so the
// index must keep numHashes / INDEX_ENTRIES under MAX_RANGE or lookups miss entries.
#if CONFIG_IDF_TARGET_ESP32S3
static const int INDEX_ENTRIES = 16384;  // 80 KB; 8 MB flash holds ~1M hashes (~64/bucket), fine to ~4M
#else
static const int INDEX_ENTRIES = 4096;   // 20 KB; fine up to ~1M hashes, 4 MB flash holds far fewer
#endif
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket

// ---- globals ----
// Health markers, read by healthTask (see "health" below). Written without locks: each is
// one aligned word, and a stale read only makes a diagnostic line a moment out of date.
volatile uint32_t loopBeat = 0, dnsBeat = 0;            // millis() when loop() / dnsTask last ran
volatile uint8_t  relayStage = 0;                       // what tlsTask is doing (RELAY_STAGES)
volatile uint32_t relayStageSince = 0;
static const char* const RELAY_STAGES[] = { "idle", "handshake", "read-request", "connect-inner", "send-inner", "relay", "close" };
static inline void relayAt(uint8_t st) { relayStage = st; relayStageSince = millis(); }
// The dashboard's WebServer listens on loopback only. Browsers reach it through the TLS
// front end on :443 (see "HTTPS"), which relays each decrypted request here; :80 only
// redirects to https. The setup portal has its own plain-HTTP server on the WPA2 setup AP.
static const uint16_t INNER_PORT = 8080;
WebServer web(IPAddress(127, 0, 0, 1), INNER_PORT);
WebServer portalWeb(80);
WiFiServer httpRedirect(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0, totalForeign = 0;

// The DNS task and the web/OTA side (loop) share the client table, custom domains, and the
// blocklist file + index. One recursive mutex guards all of it; nobody holds it across
// network I/O or a download, only across the brief reads/updates themselves.
static SemaphoreHandle_t stateMutex;
struct StateLock {
  StateLock()  { xSemaphoreTakeRecursive(stateMutex, portMAX_DELAY); }
  ~StateLock() { xSemaphoreGiveRecursive(stateMutex); }
};

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;
// Exceptions: domains (and their subdomains) that are never blocked, whatever the blocklist
// or the custom list says. Kept in /allow.txt.
static const int MAX_ALLOW = 100;
String allowDom[MAX_ALLOW]; uint64_t allowHash[MAX_ALLOW]; int numAllow = 0;

// Bans live only in this list (persisted to /banned.txt), never in the client table: the
// table is a best-effort stats cache that evicts, so a ban stored there could be pushed out
// by a flood of spoofed source addresses, and banned devices that hadn't queried yet since
// boot used to be dropped from the file whenever any other ban changed.
// A ban is by MAC address whenever the device's MAC is known, so a banned device can't get
// around it by changing its IP, and whoever gets its old IP later isn't banned. MACs come
// from the ARP table, so they're only known for devices on our own subnet that have talked
// to us. Others (behind a router, or not seen yet) are banned by IP, and the entry switches
// to their MAC once it's seen. A device can still change (or randomize) its MAC.
struct Ban { uint32_t ip; uint8_t mac[6]; };   // mac all zero = IP-only
static const int MAX_BAN = 32;
Ban bans[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
// Upper bound keeps updateIntervalH * 3600000 inside uint32 (it wraps past ~1193 h, and a
// wrapped interval near 0 re-downloads and rewrites the flash partition on every loop).
static const uint32_t UPDATE_MIN_H = 1, UPDATE_MAX_H = 720;
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start
// The portal's AP is open, and a configured device also lands in it whenever WiFi fails at
// boot (router reboot, power cut, or someone jamming it). Unless BOOT was held at power-on,
// saving there needs the current admin password: otherwise anyone in radio range could
// point the device at their own AP and set an admin password of their choosing.
bool        portalRecovery = false; // BOOT held at power-on: physical access, no password needed
uint8_t     portalFails = 0;        // wrong current-password attempts since boot
static const uint8_t PORTAL_MAX_FAILS = 5;

// Admin auth. Prebuilt (web-flasher) images only have the placeholder secrets.h, whose
// passwords are public, so the real ones are set in the setup portal and kept in NVS --
// as a salted hash, never in plaintext (see "admin password" below). A non-placeholder
// secrets.h still works for source builders. With neither, every state-changing endpoint
// stays locked and network OTA is not started at all.
bool    adminSet = false;           // an admin password exists (false -> locked)
uint8_t adminSalt[16], adminHash[32];
String  otaHashHex;                 // MD5 hex for ArduinoOTA ("" = OTA disabled)
static const size_t MIN_ADMIN_PASS = 8;

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// BOOT button: held at power-on = recovery; pressed at runtime = approve a pending action.
#if CONFIG_IDF_TARGET_ESP32C3
static const int BOOT_PIN = 9;      // C3 BOOT button
#else
static const int BOOT_PIN = 0;      // classic ESP32 and S3 BOOT button (GPIO9 is a flash pin on the classic ESP32)
#endif
// LED that blinks while an action waits for the button. -DCONFIRM_LED=-1 to disable.
#ifndef CONFIRM_LED
#if CONFIG_IDF_TARGET_ESP32C3
#define CONFIRM_LED 8               // C3 SuperMini blue LED (active low)
#define CONFIRM_LED_ON LOW
#elif CONFIG_IDF_TARGET_ESP32S3
#define CONFIRM_LED 48              // S3 DevKitC-1 WS2812 RGB LED (GPIO38 on v1.1 boards)
#define CONFIRM_LED_RGB 1
#else
#define CONFIRM_LED 2               // most esp32dev boards (active high)
#define CONFIRM_LED_ON HIGH
#endif
#endif
#ifndef CONFIRM_LED_ON
#define CONFIRM_LED_ON LOW
#endif

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

static void buildFlashIndex() {
  if (!blocklist || numHashes == 0) return;
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    blocklist.seek((uint32_t)pos * HASH_BYTES);
    blocklist.read(blIndex[i], HASH_BYTES);
  }
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  uint32_t rangeCount = endPos - startPos + 1;
  if (rangeCount > (uint32_t)MAX_RANGE) rangeCount = MAX_RANGE;

  blocklist.seek((uint32_t)startPos * HASH_BYTES);
  blocklist.read(rangeBuf, (uint32_t)rangeCount * HASH_BYTES);

  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
}

static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached (a short linear scan) to avoid serving stale answers.
static bool isBlockedHash(uint64_t h) {
  if (inCustom(h)) return true;
  uint32_t slot = h & (CACHE_SIZE - 1);
  if (cacheValid[slot]) {
    uint8_t want[HASH_BYTES]; packHash(h, want);
    bool same = true;
    for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
    if (same) return cacheRes[slot] != 0;
  }
  bool res = inFlash(h);
  cacheValid[slot] = 1;
  cacheRes[slot] = res ? 1 : 0;
  packHash(h, cacheKey[slot]);
  return res;
}

static bool inAllow(uint64_t h) { for (int i = 0; i < numAllow; i++) if (allowHash[i] == h) return true; return false; }

static bool isBlocked(const char* domain) {
  // An exception for a domain or any parent of it wins over every block: "allow
  // whatsapp.com" lets web.whatsapp.com through even when a list blocks it by name.
  if (numAllow) {
    const char* p = domain;
    while (p && *p) {
      if (inAllow(fnv40(p, strlen(p)))) return false;
      const char* dot = strchr(p, '.'); if (!dot) break;
      const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
    }
  }
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (isBlockedHash(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
// Normalize a custom domain the way queries are matched (lowercase, no "www.", no
// leading "*." / "." or trailing dot) and check it's a plain hostname: letters, digits,
// '-' and '_', dot-separated labels of 1-63 chars, at least two labels, 253 chars max.
// Anything else can't match a query anyway, and control characters or quotes would
// break /custom.txt (one domain per line) and the dashboard's JSON.
static const char* normDomain(String& d) {
  d.trim(); d.toLowerCase();
  while (d.startsWith("*.") || d.startsWith(".")) d.remove(0, d.startsWith("*.") ? 2 : 1);
  if (d.endsWith(".")) d.remove(d.length() - 1);
  if (d.startsWith("www.")) d.remove(0, 4);
  if (!d.length()) return "enter a domain, like ads.example.com";
  if (d.length() > 253) return "domain is longer than 253 characters";
  int label = 0, dots = 0;
  for (char ch : d) {
    if (ch == '.') {
      if (!label) return "empty label (two dots in a row?)";
      dots++; label = 0;
    } else if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
      if (++label > 63) return "a label is longer than 63 characters";
    } else {
      return "only letters, digits, '-', '_' and '.' are allowed (enter a domain, not a URL)";
    }
  }
  if (!dots) return "needs at least one dot, like example.com";
  return nullptr;
}
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n');
    if (normDomain(l)) continue;                   // skips blank lines and anything older firmware let in
    bool dup = false;
    for (int i = 0; i < numCustom; i++) if (customDom[i] == l) { dup = true; break; }
    if (!dup) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
// Returns nullptr on success, else why it was refused. d is normalized in place.
static const char* addCustom(String& d) {
  if (const char* why = normDomain(d)) return why;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return "already blocked";
  if (numCustom >= MAX_CUSTOM) return "custom list is full (200 domains)";
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; saveCustom(); return nullptr;
}
static void removeCustom(String& d) {
  if (normDomain(d)) return;                       // invalid: can't be in the list
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
// Exceptions, stored and checked the same way as custom domains.
static void loadAllow() {
  numAllow = 0; File f = LittleFS.open("/allow.txt", "r"); if (!f) return;
  while (f.available() && numAllow < MAX_ALLOW) {
    String l = f.readStringUntil('\n');
    if (normDomain(l)) continue;
    bool dup = false;
    for (int i = 0; i < numAllow; i++) if (allowDom[i] == l) { dup = true; break; }
    if (!dup) { allowDom[numAllow] = l; allowHash[numAllow] = fnv40(l.c_str(), l.length()); numAllow++; }
  }
  f.close();
}
static void saveAllow() { File f = LittleFS.open("/allow.txt", "w"); if (!f) return; for (int i = 0; i < numAllow; i++) f.println(allowDom[i]); f.close(); }
static const char* addAllow(String& d) {
  if (const char* why = normDomain(d)) return why;
  for (int i = 0; i < numAllow; i++) if (allowDom[i] == d) return nullptr;      // already allowed: not an error (quick picks re-add)
  if (numAllow >= MAX_ALLOW) return "exception list is full (100 domains)";
  allowDom[numAllow] = d; allowHash[numAllow] = fnv40(d.c_str(), d.length()); numAllow++; saveAllow(); return nullptr;
}
static void removeAllow(String& d) {
  if (normDomain(d)) return;
  for (int i = 0; i < numAllow; i++) if (allowDom[i] == d) {
    for (int j = i; j < numAllow - 1; j++) { allowDom[j] = allowDom[j+1]; allowHash[j] = allowHash[j+1]; }
    numAllow--; saveAllow(); return;
  }
}
static bool macKnown(const uint8_t* m) { for (int i = 0; i < 6; i++) if (m[i]) return true; return false; }
static bool parseMac(const String& s, uint8_t* mac) {
  unsigned v[6];
  if (sscanf(s.c_str(), "%2x:%2x:%2x:%2x:%2x:%2x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return false;
  for (int i = 0; i < 6; i++) mac[i] = (uint8_t)v[i];
  return true;
}
static bool banMatches(const Ban& b, uint32_t ip, const uint8_t* mac) {
  return macKnown(b.mac) ? macKnown(mac) && !memcmp(b.mac, mac, 6) : b.ip == ip;
}
static bool isBanned(uint32_t ip, const uint8_t* mac) {
  for (int i = 0; i < numBanned; i++) if (banMatches(bans[i], ip, mac)) return true;
  return false;
}
// /banned.txt: one ban per line, "ip" or "ip mac".
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) {
    String l = f.readStringUntil('\n'); l.trim();
    int sp = l.indexOf(' ');
    IPAddress ip; Ban b = {};
    if (!ip.fromString(sp < 0 ? l : l.substring(0, sp))) continue;
    b.ip = (uint32_t)ip;
    if (sp >= 0 && !parseMac(l.substring(sp + 1), b.mac)) memset(b.mac, 0, 6);
    bans[numBanned++] = b;
  }
  f.close();
}
static void saveBanned() {
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) {
    const Ban& b = bans[i];
    if (macKnown(b.mac)) f.printf("%s %02x:%02x:%02x:%02x:%02x:%02x\n", IPAddress(b.ip).toString().c_str(),
                                  b.mac[0], b.mac[1], b.mac[2], b.mac[3], b.mac[4], b.mac[5]);
    else f.println(IPAddress(b.ip).toString());
  }
  f.close();
}
// Ban or unban the device at ip/mac (mac all zero if unknown). Returns false only if
// banning and the list is full.
static bool setBanned(uint32_t ip, const uint8_t* mac, bool ban) {
  if (!ban) {
    bool changed = false;
    for (int i = 0; i < numBanned; ) {
      if (banMatches(bans[i], ip, mac)) { bans[i] = bans[--numBanned]; changed = true; }
      else i++;
    }
    if (changed) saveBanned();
    return true;
  }
  if (isBanned(ip, mac)) return true;
  if (numBanned >= MAX_BAN) return false;
  Ban& b = bans[numBanned++]; b.ip = ip; memcpy(b.mac, mac, 6);
  saveBanned();
  return true;
}
// Ban check for a DNS query. Also keeps the list current: an IP-only ban picks up the
// device's MAC once it's known, and a MAC ban records the device's latest IP (for display).
static bool checkBan(uint32_t ip, const uint8_t* mac) {
  bool known = macKnown(mac), hit = false, dirty = false;
  for (int i = 0; i < numBanned; i++) {
    Ban& b = bans[i];
    if (macKnown(b.mac)) {
      if (!known || memcmp(b.mac, mac, 6)) continue;
      hit = true;
      if (b.ip != ip) { b.ip = ip; dirty = true; }
    } else if (b.ip == ip) {
      hit = true;
      if (known) { memcpy(b.mac, mac, 6); dirty = true; }
    }
  }
  if (dirty) {                                   // learning a MAC can duplicate another entry
    for (int i = 0; i < numBanned; i++)
      for (int j = i + 1; j < numBanned; )
        if (macKnown(bans[i].mac) && !memcmp(bans[i].mac, bans[j].mac, 6)) bans[j] = bans[--numBanned]; else j++;
    saveBanned();
  }
  return hit;
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
// The MAC is looked up again on every call (a short ARP-table scan), so an IP that DHCP
// hands to another device doesn't keep the previous device's MAC, and bans follow the MAC.
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) {
    Dev& c = clients[i]; uint8_t m[6];
    c.lastSeen = millis(); getMac(ip, m); if (macKnown(m)) memcpy(c.mac, m, 6);
    return &c;
  }
  // Full: reuse the least recently seen entry, so new clients still get counted. Only stats
  // are lost; bans are kept separately (bans).
  Dev* c = &clients[0];
  if (numClients < MAX_CLIENTS) c = &clients[numClients++];
  else for (int i = 1; i < MAX_CLIENTS; i++) if (millis() - clients[i].lastSeen > millis() - c->lastSeen) c = &clients[i];
  c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->label = "";
  getMac(ip, c->mac); return c;
}

// ---------- DNS ----------
// DNS runs in its own task on raw non-blocking sockets, so nothing slow in loop() (a
// blocklist download, a browser upload, a firmware flash, a stuck web client) stops name
// resolution for the whole network. Forwarding is asynchronous too: a query is sent
// upstream and remembered in a small table, and the reply is matched and relayed whenever
// it arrives, so one slow upstream answer no longer holds up every other client (it used to
// block the loop for up to 1 s per query).
//
// Issue #10 still holds: a reply is only relayed if its txid, question section and source
// address/port match a query we sent, and the client's own txid is restored.
//
// Source ports are randomized too. With one fixed port for the device's lifetime, a forged
// reply only had to guess the 16-bit txid. Now upstream queries go out on a small pool of
// sockets, each bound to a random port and re-bound to a new one whenever it has nothing
// in flight. At home-network load that's a fresh port for nearly every query, so a forger
// has to guess port and txid together. A reply is only accepted on the socket its query
// left from. The pool is small because lwIP allows 16 sockets in total (web server, OTA,
// HTTPS fetch need theirs) and each queues just 6 datagrams.
static int hwRng(void*, unsigned char* b, size_t n) { esp_fill_random(b, n); return 0; }
#define STR_(x) #x
#define STR(x) STR_(x)
static const int MAX_PENDING = 32;
struct Pending {
  bool used; uint32_t cip; uint16_t cport; uint8_t cid0, cid1;
  uint16_t wid; uint16_t qlen; uint32_t qhash; uint32_t sentAt; uint8_t sock;
  uint16_t maxLen;                                      // largest reply the client takes over UDP
};
static Pending pending[MAX_PENDING];
static int dnsSock = -1;
static uint8_t dbuf[1536];   // DNS task only; fits any non-fragmented UDP reply (EDNS answers can exceed 512)

static uint32_t fnv32(const uint8_t* p, size_t n, uint32_t h = 2166136261u) {   // h: continue a running hash
  for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
  return h;
}
static int udpSocket(uint16_t port) {
  int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); if (s < 0) return -1;
  sockaddr_in a = {}; a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(s, (sockaddr*)&a, sizeof(a)) < 0) { close(s); return -1; }
  fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
  return s;
}
static void sendTo(int sock, uint32_t ip, uint16_t port, const uint8_t* p, int n) {
  sockaddr_in a = {}; a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = ip;
  sendto(sock, p, n, 0, (sockaddr*)&a, sizeof(a));
}

static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
static int buildBlocked(uint8_t* p, int qend, uint16_t qtype) {
  p[2] = 0x81; p[3] = 0x80; p[6] = 0; p[7] = (qtype == 1) ? 1 : 0; p[8] = 0; p[9] = 0; p[10] = 0; p[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(p + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
static int buildServfail(uint8_t* p, int qend) {     // question echoed, no answers
  p[2] = 0x81; p[3] = 0x82; p[6] = 0; p[7] = 0; p[8] = 0; p[9] = 0; p[10] = 0; p[11] = 0;
  return qend;
}
// Largest reply the client can take over UDP: 512, or the EDNS buffer size (RFC 6891) of
// an OPT record right after the question.
static uint16_t clientMaxLen(const uint8_t* p, int len, int qend) {
  bool onlyAdditional = !p[6] && !p[7] && !p[8] && !p[9] && (p[10] || p[11]);
  if (onlyAdditional && qend + 11 <= len && p[qend] == 0 && p[qend + 1] == 0 && p[qend + 2] == 41) {
    uint16_t sz = (p[qend + 3] << 8) | p[qend + 4];
    return sz < 512 ? 512 : sz > sizeof(dbuf) ? sizeof(dbuf) : sz;
  }
  return 512;
}
static void finishPending(Pending& q);
// Match an upstream reply to the query it answers (txid, question, and the socket it went
// out on) and relay it with the client's own txid. n is the reply's full length; only the
// first sizeof(dbuf) bytes need to be in m. A reply bigger than the client takes over UDP
// goes back as just the question with TC set, as an upstream UDP server would truncate it.
static void relayReply(uint8_t* m, int n, int sock) {
  if (n < 12) return;
  uint16_t wid = (m[0] << 8) | m[1];
  for (int i = 0; i < MAX_PENDING; i++) {
    Pending& q = pending[i];
    if (!q.used || q.wid != wid || q.sock != sock) continue;
    if (n < 12 + q.qlen || fnv32(m + 12, q.qlen) != q.qhash) break;   // not our question
    m[0] = q.cid0; m[1] = q.cid1;
    if (n > q.maxLen) { m[2] |= 0x02; memset(m + 4, 0, 8); m[5] = q.qlen ? 1 : 0; n = 12 + q.qlen; }
    sendTo(dnsSock, q.cip, q.cport, m, n);
    finishPending(q);
    break;
  }
}

#ifdef UPSTREAM_PLAIN
// ---- plain UDP upstream (opt-in: -DUPSTREAM_PLAIN, for networks that block port 853) ----
// Issue #10 still holds: a reply is only relayed if its txid, question section and source
// address/port match a query we sent, and the client's own txid is restored.
//
// Source ports are randomized too. With one fixed port for the device's lifetime, a forged
// reply only had to guess the 16-bit txid. Now upstream queries go out on a small pool of
// sockets, each bound to a random port and re-bound to a new one whenever it has nothing
// in flight. At home-network load that's a fresh port for nearly every query, so a forger
// has to guess port and txid together. A reply is only accepted on the socket its query
// left from. The pool is small because lwIP allows 16 sockets in total (web server, OTA,
// HTTPS fetch need theirs) and each queues just 6 datagrams.
static const uint32_t UPSTREAM_TIMEOUT_MS = 2500;   // then drop it; the client retries
const char* volatile upstreamStatus = "UNENCRYPTED: plain UDP upstream (built with UPSTREAM_PLAIN)";
static const int UP_SOCKS = 4;
struct UpSock { int fd; uint8_t inFlight; bool dirty; };   // dirty = used since its port was chosen
static UpSock ups[UP_SOCKS];
static int randomPortSocket() {
  for (int tries = 0; tries < 8; tries++) {             // a port in use just means pick another
    int s = udpSocket(1024 + esp_random() % (65536 - 1024));
    if (s >= 0) return s;
  }
  return -1;
}
// Re-bind every idle, used socket to a new random port. A late reply to the old port just
// gets ICMP port-unreachable, the same as an expired query. A socket that can't be reopened
// (lwIP out of sockets) stays closed and is retried on the next pass.
static void rotateUpstreamPorts() {
  for (int i = 0; i < UP_SOCKS; i++) {
    UpSock& u = ups[i];
    if (u.fd >= 0 && (u.inFlight || !u.dirty)) continue;
    if (u.fd >= 0) close(u.fd);
    u.fd = randomPortSocket(); u.dirty = false;
  }
}
static int upstreamPick(int) {                          // random open socket, least loaded
  int k = -1, start = esp_random() % UP_SOCKS;
  for (int j = 0; j < UP_SOCKS; j++) {
    int i = (start + j) % UP_SOCKS;
    if (ups[i].fd >= 0 && (k < 0 || ups[i].inFlight < ups[k].inFlight)) k = i;
  }
  return k;
}
static void upstreamSend(int k, int qlen) {
  ups[k].inFlight++; ups[k].dirty = true;
  sendTo(ups[k].fd, (uint32_t)UPSTREAM, UPSTREAM_PORT, dbuf, qlen);
}
static void finishPending(Pending& q) { q.used = false; if (ups[q.sock].inFlight) ups[q.sock].inFlight--; }
static void handleUpstreamReplies(int k) {
  for (int budget = 0; budget < 16; budget++) {
    sockaddr_in from; socklen_t fl = sizeof(from);
    int n = recvfrom(ups[k].fd, dbuf, sizeof(dbuf), MSG_DONTWAIT, (sockaddr*)&from, &fl);
    if (n < 0) break;
    if (from.sin_addr.s_addr != (uint32_t)UPSTREAM || ntohs(from.sin_port) != UPSTREAM_PORT) continue;
    relayReply(dbuf, n, k);
  }
}
static bool upstreamInit() {
  for (int i = 0; i < UP_SOCKS; i++) { ups[i].fd = -1; ups[i].inFlight = 0; ups[i].dirty = false; }
  rotateUpstreamPorts();
  for (int i = 0; i < UP_SOCKS; i++) if (ups[i].fd >= 0) return true;
  return false;
}
#else
// ---- DNS-over-TLS upstream (RFC 7858), the default ----
// Queries never leave in the clear: they go to UPSTREAM over one TLS connection to port
// 853, each as a 2-byte length plus the message, pipelined; replies come back in any order
// and are matched through the same pending table. Nobody on the path can read or forge
// them, so the UDP source-port games aren't needed. The connection opens on demand and
// reopens after the server closes it (it does when idle); TLS session resumption keeps the
// reconnects cheap. The certificate must chain to a root in CA_BUNDLE and name
// UPSTREAM_DOT_HOST. If that fails, or port 853 can't be reached, lookups get SERVFAIL:
// the device fails closed rather than falling back to plaintext (which anyone able to block
// 853 could then force). It retries with backoff, and the dashboard shows the state.
#ifndef UPSTREAM_DOT_HOST
#define UPSTREAM_DOT_HOST "dns.quad9.net"
#endif
#ifndef UPSTREAM_DOT_PORT
#define UPSTREAM_DOT_PORT 853
#endif
static const uint32_t UPSTREAM_TIMEOUT_MS = 4000;   // first query may wait for a TLS reconnect
static const uint32_t DOT_CONNECT_MS = 8000, DOT_BACKOFF_MAX_MS = 60000;
#define DOT_NAME UPSTREAM_DOT_HOST ":" STR(UPSTREAM_DOT_PORT)
static const char S_DOT_UP[]   = "encrypted: DNS-over-TLS to " DOT_NAME;
static const char S_DOT_IDLE[] = "encrypted: DNS-over-TLS to " DOT_NAME " (idle, reconnects on demand)";
static const char S_DOT_CONN[] = "DOWN: can't connect to " DOT_NAME " (port blocked?). Lookups fail until it works.";
static const char S_DOT_TLS[]  = "DOWN: TLS handshake with " DOT_NAME " failed. Lookups fail until it works.";
static const char S_DOT_CERT[] = "DOWN: " DOT_NAME " presented a certificate that doesn't check out. Lookups fail until it does.";
const char* volatile upstreamStatus = S_DOT_IDLE;
enum DotState : uint8_t { DOT_DOWN, DOT_CONNECTING, DOT_HANDSHAKE, DOT_UP };
static DotState dotState = DOT_DOWN;
static int dotFd = -1;
static mbedtls_ssl_context dotSsl;
static mbedtls_ssl_config dotConf;
static mbedtls_x509_crt dotNoCa;                       // empty: chains end "not trusted" and dotVerify decides
static mbedtls_ssl_session dotSession;
static bool dotHaveSession = false;
static uint8_t dotOut[2048];                           // framed queries not yet written
static size_t dotOutLen = 0, dotWriting = 0;           // dotWriting: length of a write mbedtls asked us to retry
static uint8_t dotMsg[sizeof(dbuf)], dotHdr[2], dotHdrHave = 0;
static uint16_t dotMsgLen = 0, dotMsgHave = 0;
static uint32_t dotSince = 0, dotRetryAt = 0, dotBackoffMs = 0;

// Same check as the framework's bundle verifier, but reading CA_BUNDLE directly: the
// framework keeps one global copy that every blocklist download frees and rebuilds, which
// could pull it out from under a handshake in this task. mbedtls verifies the chain and the
// hostname itself; this only decides whether the top certificate was issued by one of our
// roots (found by the issuer's name, then the signature checked with that root's key).
static int dotCheckSig(mbedtls_x509_crt* child, const uint8_t* key, size_t keyLen) {
  mbedtls_x509_crt parent; mbedtls_x509_crt_init(&parent);
  unsigned char hash[MBEDTLS_MD_MAX_SIZE];
  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(child->sig_md);
  int r = -1;
  if (md && !mbedtls_pk_parse_public_key(&parent.pk, key, keyLen) && mbedtls_pk_can_do(&parent.pk, child->sig_pk) &&
      !mbedtls_md(md, child->tbs.p, child->tbs.len, hash))
    r = mbedtls_pk_verify_ext(child->sig_pk, child->sig_opts, &parent.pk, child->sig_md, hash,
                              mbedtls_md_get_size(md), child->sig.p, child->sig.len);
  mbedtls_x509_crt_free(&parent);
  return r;
}
static int dotVerify(void*, mbedtls_x509_crt* crt, int, uint32_t* flags) {
  if ((*flags & ~MBEDTLS_X509_BADCERT_BAD_MD) != MBEDTLS_X509_BADCERT_NOT_TRUSTED) return 0;
  const uint8_t* p = CA_BUNDLE + 2;
  for (int i = 0, n = (CA_BUNDLE[0] << 8) | CA_BUNDLE[1]; i < n; i++) {
    size_t nl = (p[0] << 8) | p[1], kl = (p[2] << 8) | p[3];
    const uint8_t* name = p + 4; const uint8_t* key = name + nl;
    if (nl == crt->issuer_raw.len && !memcmp(name, crt->issuer_raw.p, nl) && !dotCheckSig(crt, key, kl)) { *flags = 0; break; }
    p = key + kl;
  }
  return 0;                                            // flags still set -> handshake fails
}
static int dotSend(void*, const unsigned char* b, size_t n) {
  int r = send(dotFd, b, n, 0);
  return r >= 0 ? r : (errno == EAGAIN || errno == EWOULDBLOCK) ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_NET_SEND_FAILED;
}
static int dotRecv(void*, unsigned char* b, size_t n) {
  int r = recv(dotFd, b, n, 0);
  return r >= 0 ? r : (errno == EAGAIN || errno == EWOULDBLOCK) ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_NET_RECV_FAILED;
}
// Close the connection. failed: back off before the next attempt (doubling, up to a minute).
// Queries still queued or in flight just expire; clients retry.
static void dotDrop(bool failed, const char* status) {
  if (dotFd >= 0) close(dotFd);
  dotFd = -1; dotState = DOT_DOWN;
  mbedtls_ssl_session_reset(&dotSsl);
  dotOutLen = dotWriting = 0; dotHdrHave = 0; dotMsgLen = dotMsgHave = 0;
  upstreamStatus = status;
  if (failed) {
    dotBackoffMs = dotBackoffMs ? min(dotBackoffMs * 2, DOT_BACKOFF_MAX_MS) : 2000;
    dotRetryAt = millis() + dotBackoffMs;
    if (status != S_DOT_CONN) dotHaveSession = false;   // don't resume a session that just failed
  }
}
static bool dotOpen() {
  dotFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (dotFd < 0) { dotDrop(true, S_DOT_CONN); return false; }
  fcntl(dotFd, F_SETFL, fcntl(dotFd, F_GETFL, 0) | O_NONBLOCK);
  int one = 1; setsockopt(dotFd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  sockaddr_in a = {}; a.sin_family = AF_INET; a.sin_port = htons(UPSTREAM_DOT_PORT); a.sin_addr.s_addr = (uint32_t)UPSTREAM;
  if (connect(dotFd, (sockaddr*)&a, sizeof(a)) < 0 && errno != EINPROGRESS) { dotDrop(true, S_DOT_CONN); return false; }
  mbedtls_ssl_set_hostname(&dotSsl, UPSTREAM_DOT_HOST);
  if (dotHaveSession) mbedtls_ssl_set_session(&dotSsl, &dotSession);
  dotState = DOT_CONNECTING; dotSince = millis();
  return true;
}
// Reassemble length-prefixed replies (they can span reads) and relay each complete one.
static void dotFeed(const uint8_t* p, size_t n) {
  while (n) {
    if (dotHdrHave < 2) {
      dotHdr[dotHdrHave++] = *p++; n--;
      if (dotHdrHave == 2) { dotMsgLen = (dotHdr[0] << 8) | dotHdr[1]; dotMsgHave = 0; if (!dotMsgLen) dotHdrHave = 0; }
      continue;
    }
    size_t take = min(n, (size_t)(dotMsgLen - dotMsgHave));
    if (dotMsgHave < sizeof(dotMsg))                   // past the buffer is dropped: such replies go back truncated
      memcpy(dotMsg + dotMsgHave, p, min(take, sizeof(dotMsg) - dotMsgHave));
    dotMsgHave += take; p += take; n -= take;
    if (dotMsgHave == dotMsgLen) { relayReply(dotMsg, dotMsgLen, 0); dotHdrHave = 0; }
  }
}
// Advance the connection: finish connecting, handshake, write queued queries, read replies.
static void dotPump() {
  if (dotState == DOT_DOWN) return;
  if (dotState != DOT_UP && millis() - dotSince > DOT_CONNECT_MS) { dotDrop(true, dotState == DOT_CONNECTING ? S_DOT_CONN : S_DOT_TLS); return; }
  if (dotState == DOT_CONNECTING) {
    fd_set wf; FD_ZERO(&wf); FD_SET(dotFd, &wf); timeval z = { 0, 0 };
    if (select(dotFd + 1, nullptr, &wf, nullptr, &z) <= 0) return;
    int err = 0; socklen_t el = sizeof(err);
    getsockopt(dotFd, SOL_SOCKET, SO_ERROR, &err, &el);
    if (err) { dotDrop(true, S_DOT_CONN); return; }
    dotState = DOT_HANDSHAKE;
  }
  if (dotState == DOT_HANDSHAKE) {
    int r = mbedtls_ssl_handshake(&dotSsl);
    if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) return;
    if (r) { dotDrop(true, mbedtls_ssl_get_verify_result(&dotSsl) ? S_DOT_CERT : S_DOT_TLS); return; }
    mbedtls_ssl_session_free(&dotSession); mbedtls_ssl_session_init(&dotSession);
    dotHaveSession = !mbedtls_ssl_get_session(&dotSsl, &dotSession);
    dotState = DOT_UP; dotBackoffMs = 0; upstreamStatus = S_DOT_UP;
  }
  while (dotOutLen) {
    size_t n = dotWriting ? dotWriting : dotOutLen;      // a retried write must repeat the same length
    int r = mbedtls_ssl_write(&dotSsl, dotOut, n);
    if (r == MBEDTLS_ERR_SSL_WANT_WRITE || r == MBEDTLS_ERR_SSL_WANT_READ) { dotWriting = n; break; }
    dotWriting = 0;
    if (r <= 0) { dotDrop(false, S_DOT_IDLE); return; }
    memmove(dotOut, dotOut + r, dotOutLen - r); dotOutLen -= r;
  }
  for (int budget = 0; budget < 16; budget++) {
    uint8_t buf[512];
    int r = mbedtls_ssl_read(&dotSsl, buf, sizeof(buf));
    if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) break;
    if (r <= 0) { dotDrop(false, S_DOT_IDLE); return; }  // the server closing an idle connection is normal
    dotFeed(buf, r);
  }
}
// 0 if the query can go out (opening the connection if needed), -1 to answer SERVFAIL.
static int upstreamPick(int qlen) {
  if (dotState == DOT_DOWN) {
    if ((int32_t)(millis() - dotRetryAt) < 0) return -1;   // backing off after a failure
    if (!dotOpen()) return -1;
  }
  return dotOutLen + 2 + qlen <= sizeof(dotOut) ? 0 : -1;
}
static void upstreamSend(int, int qlen) {
  dotOut[dotOutLen++] = qlen >> 8; dotOut[dotOutLen++] = qlen & 0xFF;
  memcpy(dotOut + dotOutLen, dbuf, qlen); dotOutLen += qlen;
  dotPump();                                           // send now if the connection is up
}
static void finishPending(Pending& q) { q.used = false; }
static bool upstreamInit() {
  mbedtls_ssl_init(&dotSsl); mbedtls_ssl_config_init(&dotConf);
  mbedtls_x509_crt_init(&dotNoCa); mbedtls_ssl_session_init(&dotSession);
  if (mbedtls_ssl_config_defaults(&dotConf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) return false;
  mbedtls_ssl_conf_rng(&dotConf, hwRng, nullptr);
  mbedtls_ssl_conf_authmode(&dotConf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&dotConf, &dotNoCa, nullptr);
  mbedtls_ssl_conf_verify(&dotConf, dotVerify, nullptr);
  if (mbedtls_ssl_setup(&dotSsl, &dotConf)) return false;
  mbedtls_ssl_set_bio(&dotSsl, nullptr, dotSend, dotRecv, nullptr);
  return true;
}
#endif

// Returns false if the query can't go upstream (table full, or DNS-over-TLS down); the
// caller answers SERVFAIL so the client moves on.
static bool forwardUpstream(uint32_t cip, uint16_t cport, int qlen, int qend) {
  int slot = -1;
  for (int i = 0; i < MAX_PENDING; i++) if (!pending[i].used) { slot = i; break; }
  if (slot < 0) return false;
  int k = upstreamPick(qlen);
  if (k < 0) return false;
  uint16_t wid; bool clash;
  do {                                                  // random txid not already in flight
    wid = (uint16_t)esp_random(); clash = false;
    for (int i = 0; i < MAX_PENDING; i++) if (pending[i].used && pending[i].wid == wid) { clash = true; break; }
  } while (clash);
  Pending& q = pending[slot];
  q.cip = cip; q.cport = cport; q.cid0 = dbuf[0]; q.cid1 = dbuf[1]; q.wid = wid;
  q.qlen = (qend > 12 && qend <= qlen) ? qend - 12 : 0;
  q.qhash = fnv32(dbuf + 12, q.qlen); q.sentAt = millis(); q.used = true; q.sock = k;
  q.maxLen = clientMaxLen(dbuf, qlen, qend);
  dbuf[0] = wid >> 8; dbuf[1] = wid & 0xFF;
  upstreamSend(k, qlen);
  return true;
}
static void expirePending() {
  uint32_t now = millis();
  for (int i = 0; i < MAX_PENDING; i++)
    if (pending[i].used && now - pending[i].sentAt > UPSTREAM_TIMEOUT_MS) finishPending(pending[i]);
}
// Only answer clients that can be on our network. Unrestricted, the device is an open
// resolver if port 53 is ever reachable from outside (port forward, UPnP, DMZ): anyone can
// use it, and spoofed queries make it bounce larger answers at a victim (amplification).
// Accepted: our own subnet, plus private/CGNAT/link-local ranges so routed LAN segments
// (VLANs, guest networks, Tailscale) keep working. A spoofed private source can't be used
// for amplification: the replies go to an address the internet can't reach. Build with
// -DDNS_SUBNET_ONLY to accept only our own subnet. Rejected queries are dropped silently:
// even a REFUSED would be a packet sent to a possibly spoofed address.
static uint32_t lanIp = 0, lanMask = 0;               // network byte order; refreshed by dnsTask
static bool allowedSource(uint32_t ip) {
  if (lanMask && (ip & lanMask) == (lanIp & lanMask)) return true;
#ifdef DNS_SUBNET_ONLY
  return false;
#else
  uint32_t h = ntohl(ip);
  return (h >> 24) == 10                               // 10.0.0.0/8
      || (h >> 20) == 0xAC1                            // 172.16.0.0/12
      || (h >> 16) == 0xC0A8                           // 192.168.0.0/16
      || (h >> 22) == 0x191                            // 100.64.0.0/10 (CGNAT, Tailscale)
      || (h >> 16) == 0xA9FE;                          // 169.254.0.0/16 (link-local)
#endif
}
static void handleClientQueries() {
  for (int budget = 0; budget < 32; budget++) {
    sockaddr_in from; socklen_t fl = sizeof(from);
    int qlen = recvfrom(dnsSock, dbuf, sizeof(dbuf), MSG_DONTWAIT, (sockaddr*)&from, &fl);
    if (qlen < 0) break;
    if (qlen < 13) continue;
    uint32_t cip = from.sin_addr.s_addr; uint16_t cport = ntohs(from.sin_port);
    if (!allowedSource(cip)) { totalForeign++; continue; }
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = parseQuery(dbuf, qlen, domain, &qtype, &qend);
    bool blocked;
    {
      StateLock lock;                                 // client table + blocklist are shared with the web side
      Dev* c = getClient(cip);
      blocked = checkBan(cip, c->mac) || (blockingOn && dl && numHashes && isBlocked(domain));
      if (blocked) { totalBlocked++; if (c) c->blocked++; }
      else         { totalAllowed++; if (c) c->allowed++; }
    }
    if (blocked) { int rlen = buildBlocked(dbuf, qend, qtype); sendTo(dnsSock, cip, cport, dbuf, rlen); }
    else if (!forwardUpstream(cip, cport, qlen, qend) && dl) sendTo(dnsSock, cip, cport, dbuf, buildServfail(dbuf, qend));
  }
}
static void dnsTask(void*) {
  for (;;) {
    lanIp = (uint32_t)WiFi.localIP(); lanMask = (uint32_t)WiFi.subnetMask();   // follows DHCP changes
    fd_set rf, wf; FD_ZERO(&rf); FD_ZERO(&wf); FD_SET(dnsSock, &rf); int maxfd = dnsSock;
#ifdef UPSTREAM_PLAIN
    for (int i = 0; i < UP_SOCKS; i++) if (ups[i].fd >= 0) { FD_SET(ups[i].fd, &rf); if (ups[i].fd > maxfd) maxfd = ups[i].fd; }
#else
    if (dotFd >= 0) {
      FD_SET(dotFd, &rf);
      if (dotState == DOT_CONNECTING || (dotState == DOT_UP && dotOutLen)) FD_SET(dotFd, &wf);
      if (dotFd > maxfd) maxfd = dotFd;
    }
#endif
    timeval tv = {0, 100000};                         // wake at least every 100 ms to expire
    if (select(maxfd + 1, &rf, &wf, nullptr, &tv) > 0) {
#ifdef UPSTREAM_PLAIN
      for (int i = 0; i < UP_SOCKS; i++) if (ups[i].fd >= 0 && FD_ISSET(ups[i].fd, &rf)) handleUpstreamReplies(i);
#endif
      if (FD_ISSET(dnsSock, &rf)) handleClientQueries();
    }
#ifdef UPSTREAM_PLAIN
    rotateUpstreamPorts();
#else
    dotPump();
#endif
    expirePending();
    dnsBeat = millis();
  }
}
static bool startDns() {
  dnsSock = udpSocket(DNS_PORT);
  if (dnsSock < 0 || !upstreamInit()) return false;
  // Stack is in bytes; lookups read flash through LittleFS, and a DNS-over-TLS handshake
  // (ECDHE + certificate checks) runs in this task too.
  return xTaskCreate(dnsTask, "dns", 12288, nullptr, 3, nullptr) == pdPASS;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) {          // JSON string body: quotes, backslash, control chars
  String o; o.reserve(s.length());
  for (char ch : s) {
    if (ch == '"' || ch == '\\') { o += '\\'; o += ch; }
    else if ((uint8_t)ch < 0x20) { char u[7]; snprintf(u, sizeof(u), "\\u%04x", (uint8_t)ch); o += u; }
    else o += ch;
  }
  return o;
}
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

// Upstream shipped every state-changing/OTA endpoint with zero authentication —
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Basic Auth alone isn't enough here: these are GET endpoints with side effects,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin — including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// c3adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "c3-adblock";

// The TLS front end tells the dashboard who the browser is with "X-C3-Peer: <ip> <token>",
// after dropping any X-C3-Peer the browser sent. <token> is random per boot, so a request
// that somehow reached the loopback server without going through the front end can't claim
// an address (and so can't dodge the per-IP lockout or another device's BOOT approval).
static const char* PEER_HEADER = "X-C3-Peer";
static char peerToken[33];
static uint32_t clientIp() {             // 0 = not relayed by the front end
  String v = web.header(PEER_HEADER);
  int sp = v.indexOf(' ');
  IPAddress ip;
  if (sp < 0 || !peerToken[0] || v.substring(sp + 1) != peerToken || !ip.fromString(v.substring(0, sp))) return 0;
  return (uint32_t)ip;
}

// DNS rebinding: a page on evil.example can re-point its own hostname at this device's
// LAN IP. Its fetch() is then "same-origin", so it can set the CSRF header above and
// read /stats.json. The browser still sends Host: evil.example, so only answer requests
// addressed to a name or IP that really is this device.
static bool hostOk() {
  if (!clientIp()) return false;
  String h = web.hostHeader(); h.toLowerCase();
  int colon = h.indexOf(':'); if (colon >= 0) h = h.substring(0, colon);
  if (h.endsWith(".")) h.remove(h.length() - 1);
  return h == "c3adblock.local" || h == "c3adblock" || h == WiFi.localIP().toString();
}
static bool requireHost() {
  if (hostOk()) return true;
  web.send(403, "text/plain", "bad Host header (use https://c3adblock.local or the device IP)");
  return false;
}

// ---------- audit log ----------
// The last AUDIT_SIZE admin events (actions, wrong passwords, lockouts, confirmations) in a
// RAM ring buffer, shown on the dashboard. If something changes a setting, you can see when
// and from which device. Cleared on reboot; nothing is written to flash.
static const int AUDIT_SIZE = 32;
struct AuditEntry { uint32_t ms; uint32_t ip; uint8_t mac[6]; char what[14]; char detail[42]; };
static AuditEntry auditLog[AUDIT_SIZE];
static int auditHead = 0, auditCount = 0;
static void copySafe(char* dst, size_t cap, const char* src) {   // printable ASCII only: keeps the JSON valid
  size_t i = 0;
  for (; src && src[i] && i < cap - 1; i++) dst[i] = (src[i] >= 0x20 && src[i] < 0x7f) ? src[i] : '?';
  dst[i] = 0;
}
// ip 0 = the device itself (a BOOT press, a timeout).
static void auditIp(uint32_t ip, const char* what, const String& detail = "") {
  AuditEntry& e = auditLog[auditHead];
  e.ms = millis(); e.ip = ip;
  if (ip) { StateLock lock; getMac(ip, e.mac); } else memset(e.mac, 0, 6);
  copySafe(e.what, sizeof(e.what), what);
  copySafe(e.detail, sizeof(e.detail), detail.c_str());
  auditHead = (auditHead + 1) % AUDIT_SIZE;
  if (auditCount < AUDIT_SIZE) auditCount++;
  Serial.printf("[audit] %s %s %s\n", ip ? IPAddress(ip).toString().c_str() : "device", e.what, e.detail);
}
static void audit(const char* what, const String& detail = "") { auditIp(clientIp(), what, detail); }

// ---------- login lockout ----------
// Basic Auth has no rate limit of its own, so a script on the LAN could guess passwords as
// fast as the chip answers. After LOCK_AFTER wrong passwords from one IP, that IP is
// refused (429) without checking the password, for LOCK_BASE_S seconds, doubling with each
// further failure up to LOCK_MAX_S. A correct password clears the count; so does an hour
// without failures. A request with no Authorization header at all (the browser's first try,
// before it shows the login prompt) doesn't count.
static const int LOCK_SLOTS = 16;
static const uint8_t LOCK_AFTER = 5;
static const uint32_t LOCK_BASE_S = 30, LOCK_MAX_S = 3600, LOCK_FORGET_MS = 3600000UL;
struct LockEntry { uint32_t ip; uint8_t fails; uint32_t lastFail, lockedUntil; };
static LockEntry locks[LOCK_SLOTS];
static LockEntry* findLock(uint32_t ip) {
  for (int i = 0; i < LOCK_SLOTS; i++) if (locks[i].ip == ip && locks[i].fails) return &locks[i];
  return nullptr;
}
static uint32_t lockRemainingS(const LockEntry* e) {
  int32_t ms = (int32_t)(e->lockedUntil - millis());
  return (e->fails >= LOCK_AFTER && ms > 0) ? (ms + 999) / 1000 : 0;
}
static uint32_t lockedFor(uint32_t ip) {   // seconds left, 0 = not locked
  LockEntry* e = findLock(ip);
  if (!e) return 0;
  if (!lockRemainingS(e) && millis() - e->lastFail > LOCK_FORGET_MS) { e->fails = 0; return 0; }
  return lockRemainingS(e);
}
static void recordAuthFail(uint32_t ip) {
  LockEntry* e = findLock(ip);
  if (!e) {   // new slot: a free one, else evict the least recently failing
    e = &locks[0];
    for (int i = 0; i < LOCK_SLOTS; i++) {
      if (!locks[i].fails) { e = &locks[i]; break; }
      if (locks[i].lastFail - e->lastFail > 0x7fffffffUL) e = &locks[i];   // older (wrap-safe)
    }
    e->ip = ip; e->fails = 0;
  }
  e->lastFail = millis();
  if (e->fails < 255) e->fails++;
  if (e->fails >= LOCK_AFTER) {
    uint32_t s = LOCK_BASE_S << min(e->fails - LOCK_AFTER, 7);   // 30 s, 60 s, ... capped
    if (s > LOCK_MAX_S) s = LOCK_MAX_S;
    e->lockedUntil = millis() + s * 1000UL;
    auditIp(ip, "locked out", String(e->fails) + " wrong passwords, " + s + " s");
  } else {
    auditIp(ip, "bad password", web.uri());
  }
}
static void clearAuthFails(uint32_t ip) { LockEntry* e = findLock(ip); if (e) e->fails = 0; }

// Device-wide limit. The per-IP lockout alone can be sidestepped by an attacker who spreads
// guesses over many LAN addresses (each new IP starts at zero, and 16 slots means old
// entries get evicted). So every wrong password, from anywhere, also adds GLOBAL_COST_MS
// of "debt" that drains in real time; while debt exceeds GLOBAL_BURST_MS, every client is
// refused without a password check. That allows a burst of ~20 wrong guesses, then one
// per 45 s across the whole network, whatever the number of addresses. Since that can lock
// the owner out too, a BOOT press with nothing pending clears it (and per-IP lockouts).
static const uint32_t GLOBAL_COST_MS = 45000, GLOBAL_BURST_MS = 20 * GLOBAL_COST_MS;
static uint32_t gDebtMs = 0, gDebtAt = 0;
static uint32_t globalDebt() { uint32_t e = millis() - gDebtAt; return gDebtMs > e ? gDebtMs - e : 0; }
static uint32_t globalLockedFor() {        // seconds left, 0 = not locked
  uint32_t d = globalDebt();
  return d > GLOBAL_BURST_MS ? (d - GLOBAL_BURST_MS + 999) / 1000 : 0;
}
static void recordGlobalFail() {
  bool was = globalLockedFor();
  gDebtMs = globalDebt() + GLOBAL_COST_MS; gDebtAt = millis();
  if (!was && globalLockedFor()) auditIp(0, "global lock", "too many wrong passwords, all clients refused");
}
static bool clearAllLockouts() {           // true if anything was locked or counting
  bool any = globalDebt() > 0;
  for (int i = 0; i < LOCK_SLOTS; i++) if (locks[i].fails) { any = true; locks[i].fails = 0; }
  gDebtMs = 0;
  return any;
}

// ---------- admin password ----------
// NVS "auth" keeps a random 16-byte salt and PBKDF2-HMAC-SHA256(password, salt) ("salt",
// "hash"), so dumping the flash doesn't hand over the password. Network OTA is the
// exception: espota's challenge protocol needs MD5(password) on the device ("otamd5"), and
// ArduinoOTA can't use anything slower. That MD5 is unsalted and fast to brute-force, so a
// weak admin password can still be recovered from a flash dump: use a long one, or enable
// flash encryption (guide/security.md). Older firmware stored the password itself ("pass"); loadAuth()
// converts that on first boot.
static const uint32_t ADMIN_ITER = 10000;
static bool isPlaceholder(const char* s, const char* placeholder) { return !s || !*s || strcmp(s, placeholder) == 0; }
static bool pbkdf2(mbedtls_md_type_t t, const uint8_t* pw, size_t pwl, const uint8_t* salt, size_t sl,
                   uint32_t iter, uint8_t* out, size_t outl) {
  mbedtls_md_context_t ctx; mbedtls_md_init(&ctx);
  bool ok = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(t), 1) == 0 &&
            mbedtls_pkcs5_pbkdf2_hmac(&ctx, pw, pwl, salt, sl, iter, outl, out) == 0;
  mbedtls_md_free(&ctx);
  return ok;
}
static bool ctEqual(const uint8_t* a, const uint8_t* b, size_t n) {   // constant time
  uint8_t d = 0; for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i]; return d == 0;
}
static String md5Hex(const String& s) { MD5Builder m; m.begin(); m.add(s); m.calculate(); return m.toString(); }
static bool deriveAdmin(const String& pw, const uint8_t* salt, uint8_t* out) {
  return pbkdf2(MBEDTLS_MD_SHA256, (const uint8_t*)pw.c_str(), pw.length(), salt, 16, ADMIN_ITER, out, 32);
}
static bool verifyAdminPass(const String& pw) {
  uint8_t h[32];
  return adminSet && deriveAdmin(pw, adminSalt, h) && ctEqual(h, adminHash, 32);
}
// Hash `pw` as the admin password; with persist, also save it (replacing any plaintext).
static void setAdminPass(const String& pw, bool persist) {
  esp_fill_random(adminSalt, sizeof(adminSalt));
  adminSet = deriveAdmin(pw, adminSalt, adminHash);
  if (!adminSet || !persist) return;
  prefs.begin("auth", false);
  prefs.putBytes("salt", adminSalt, sizeof(adminSalt)); prefs.putBytes("hash", adminHash, sizeof(adminHash));
  prefs.putString("otamd5", md5Hex(pw)); prefs.remove("pass");
  prefs.end();
}
// NVS (set in the portal) wins; a real secrets.h value is the fallback for source builds.
static void loadAuth() {
  adminSet = false;
  String otaMd5;
  prefs.begin("auth", true);
  String legacy = prefs.getString("pass", "");
  if (prefs.getBytesLength("salt") == sizeof(adminSalt) && prefs.getBytesLength("hash") == sizeof(adminHash)) {
    prefs.getBytes("salt", adminSalt, sizeof(adminSalt)); prefs.getBytes("hash", adminHash, sizeof(adminHash));
    otaMd5 = prefs.getString("otamd5", "");
    adminSet = true;
  }
  prefs.end();
  if (legacy.length()) {                         // plaintext from older firmware: hash it, then drop it
    if (!adminSet) { setAdminPass(legacy, true); otaMd5 = md5Hex(legacy); Serial.println("[auth] stored admin password converted to a salted hash"); }
    else { prefs.begin("auth", false); prefs.remove("pass"); prefs.end(); }
  }
  if (!adminSet && !isPlaceholder(WEB_PASS, "CHANGE_ME_WEB_PASSWORD")) { setAdminPass(WEB_PASS, false); otaMd5 = md5Hex(WEB_PASS); }
  otaHashHex = isPlaceholder(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") ? (adminSet ? otaMd5 : String("")) : md5Hex(OTA_PASS);
}
// Basic Auth checked against the hash. PBKDF2 takes a noticeable fraction of a second, so a
// header that verified once is remembered (its SHA-256, in RAM) and the dashboard's polling
// doesn't pay for it every 3 s. Only Basic is accepted: Digest would need the password.
static uint8_t goodAuth[32]; static bool goodAuthSet = false;
static bool basicAuthOk() {
  if (!adminSet || !web.hasHeader("Authorization")) return false;
  String b = web.header("Authorization");
  if (!b.startsWith("Basic ")) return false;
  b = b.substring(6); b.trim();
  if (!b.length() || b.length() > 252) return false;
  uint8_t d[32];
  if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const uint8_t*)b.c_str(), b.length(), d)) return false;
  if (goodAuthSet && ctEqual(d, goodAuth, 32)) return true;
  uint8_t raw[192]; size_t n = 0;
  if (mbedtls_base64_decode(raw, sizeof(raw) - 1, &n, (const uint8_t*)b.c_str(), b.length())) return false;
  raw[n] = 0;
  char* colon = (char*)memchr(raw, ':', n);
  bool ok = false;
  if (colon) { *colon = 0; ok = strcmp((char*)raw, WEB_USER) == 0 && verifyAdminPass(String(colon + 1)); }
  memset(raw, 0, sizeof(raw));
  if (ok) { memcpy(goodAuth, d, 32); goodAuthSet = true; }
  return ok;
}

// ---------- auth ----------
enum AuthResult { AUTH_OK, AUTH_HOST, AUTH_NOPASS, AUTH_CSRF, AUTH_LOCKED, AUTH_PROMPT, AUTH_CONFIRM };
static AuthResult checkAuth() {
  if (!hostOk()) return AUTH_HOST;
  if (!adminSet) return AUTH_NOPASS;
  if (web.header(CSRF_HEADER) != CSRF_VALUE) return AUTH_CSRF;
  uint32_t ip = clientIp();
  if (lockedFor(ip) || globalLockedFor()) return AUTH_LOCKED;
  if (basicAuthOk()) { clearAuthFails(ip); return AUTH_OK; }
  if (web.hasHeader("Authorization")) { recordAuthFail(ip); recordGlobalFail(); }
  return AUTH_PROMPT;
}
static void sendAuthError(AuthResult r) {
  switch (r) {
    case AUTH_HOST:    web.send(403, "text/plain", "bad Host header (use https://c3adblock.local or the device IP)"); break;
    case AUTH_NOPASS:  web.send(403, "text/plain", "no admin password set: hold BOOT while powering on to run setup"); break;
    case AUTH_CSRF:    web.send(403, "text/plain", "missing CSRF header"); break;
    case AUTH_LOCKED: {
      uint32_t ipS = lockedFor(clientIp()), gS = globalLockedFor(), s = max(ipS, gS);
      web.sendHeader("Retry-After", String(s));
      web.send(429, "text/plain", String(ipS >= gS ? "too many wrong passwords from this device"
                                                   : "too many wrong passwords on the network")
                                  + ": try again in " + String(s) + " s, or press the device's BOOT button to clear it");
      break;
    }
    case AUTH_CONFIRM: web.send(428, "text/plain", "not confirmed: press the BOOT button on the device to approve this"); break;
    default:           web.requestAuthentication(); break;
  }
}
static bool requireAuth() {
  AuthResult r = checkAuth();
  if (r == AUTH_OK) return true;
  sendAuthError(r);
  return false;
}

// ---------- physical confirmation ----------
// The checks above can't tell the owner from software acting with the owner's credentials:
// an AI browser agent in a tab where the dashboard is logged in, a prompt-injected script,
// anything that sniffed the password off the LAN. For actions that can take the device over
// or quietly turn blocking off, someone also has to press BOOT on the device itself:
//   1. the dashboard asks /confirm?a=<action>; the LED blinks
//   2. BOOT pressed within CONFIRM_WAIT_MS -> that action is approved for CONFIRM_USE_MS,
//      for the IP that asked, once
//   3. the real request consumes the approval (428 without one)
// An approval is for one exact request, not just an action name: /confirm also takes
// p=<parameter> (the new update URL, the pause length, "<size>:<fnv32>" of an upload) and
// the real request must match it. Otherwise something else in the same browser (same IP)
// could use your press for its own URL or file. Nothing can replace a pending request, not
// even from the same IP; it has to be cancelled (/confirm?cancel=1), which is audited.
// While physical confirmation is on, network OTA (espota) also only answers for a minute
// after a BOOT press made with nothing pending. It can be turned off on the dashboard
// (which itself needs a press); BOOT-at-power-on recovery turns it back on.
static const uint32_t CONFIRM_WAIT_MS = 30000, CONFIRM_USE_MS = 60000, OTA_WINDOW_MS = 60000;
static const char* const CONFIRM_ACTIONS[] = { "update", "upload", "setupdate", "forgetwifi", "phys", "pause" };
bool physConfirm = true;                         // NVS auth/phys
// ph = fnv32 of the parameter; detail = the parameter as shown on the dashboard (may be cut short)
struct Confirm { char action[12]; char detail[48]; uint32_t ip, until, ph; bool approved; };
static Confirm pend = {};                        // action[0] == 0: nothing pending
static uint32_t otaWindowUntil = 0;
static bool confirmActive() { return pend.action[0] && (int32_t)(pend.until - millis()) > 0; }
static bool otaWindowOpen() { return otaWindowUntil && (int32_t)(otaWindowUntil - millis()) > 0; }
static void ledSet(bool on) {
  if (CONFIRM_LED < 0) return;
#ifdef CONFIRM_LED_RGB
  uint8_t v = on ? 64 : 0;                       // addressable LED: dim white or off
  neopixelWrite(CONFIRM_LED, v, v, v);
#else
  digitalWrite(CONFIRM_LED, on ? CONFIRM_LED_ON : !CONFIRM_LED_ON);
#endif
}
static void loadPhys() { prefs.begin("auth", true); physConfirm = prefs.getBool("phys", true); prefs.end(); }
static void savePhys() { prefs.begin("auth", false); prefs.putBool("phys", physConfirm); prefs.end(); }
static uint32_t paramHash(const String& p) { return fnv32((const uint8_t*)p.c_str(), p.length()); }
static bool approvedFor(const char* action) {
  return confirmActive() && pend.approved && !strcmp(pend.action, action) && pend.ip == clientIp();
}
// True if this request may do `action` with `param` now; consumes the approval.
static bool consumeConfirm(const char* action, const String& param = "") {
  if (!physConfirm) return true;
  if (!approvedFor(action) || pend.ph != paramHash(param)) return false;
  pend.action[0] = 0;
  return true;
}
static bool requireConfirm(const char* action, const String& param = "") {
  if (consumeConfirm(action, param)) return true;
  audit("unconfirmed", action);
  sendAuthError(AUTH_CONFIRM);
  return false;
}
// An upload's parameter ("<size>:<fnv32 hex>") is only known once the whole file is in,
// so the approval is taken when the file starts and the file is checked when it ends.
struct FileGate { bool on; uint32_t want, h; size_t n; };
static FileGate fgate = {};
static bool gateStart(const char* action) {
  fgate = {};
  if (!physConfirm) return true;
  if (!approvedFor(action)) return false;
  fgate.on = true; fgate.want = pend.ph; fgate.h = 2166136261u;
  pend.action[0] = 0;
  return true;
}
static void gateWrite(const uint8_t* p, size_t n) { fgate.h = fnv32(p, n, fgate.h); fgate.n += n; }
static bool gateOk() {                           // the received file is the one approved
  if (!fgate.on) return true;
  char tag[24]; snprintf(tag, sizeof(tag), "%u:%08x", (unsigned)fgate.n, (unsigned)fgate.h);
  return paramHash(tag) == fgate.want;
}
static void handleConfirm() {
  if (!requireAuth()) return;
  if (web.hasArg("cancel")) {                    // /confirm?cancel=1: drop this device's own request
    if (!confirmActive()) { web.send(200, "text/plain", "nothing pending"); return; }
    if (pend.ip != clientIp()) { web.send(409, "text/plain", "that request belongs to another device"); return; }
    audit("cancelled", pend.action); pend.action[0] = 0;
    web.send(200, "text/plain", "cancelled");
    return;
  }
  String a = web.arg("a"), p = web.arg("p");
  bool known = false;
  for (const char* k : CONFIRM_ACTIONS) if (a == k) known = true;
  if (!known) { web.send(400, "text/plain", "unknown action"); return; }
  if (!physConfirm) { web.send(200, "text/plain", "approved"); return; }
  // One request at a time, and nobody swaps theirs in under a pending one, the same IP included.
  if (confirmActive()) {
    String left = String((pend.until - millis()) / 1000 + 1) + " s";
    if (pend.ip == clientIp())
      web.send(409, "text/plain", "this device already has a request waiting (" + String(pend.action) +
                                  "); cancel it or wait " + left);
    else
      web.send(409, "text/plain", "another device is waiting for a BOOT press; try again in " + left);
    return;
  }
  copySafe(pend.action, sizeof(pend.action), a.c_str());
  copySafe(pend.detail, sizeof(pend.detail), p.c_str());
  pend.ph = paramHash(p);
  pend.ip = clientIp(); pend.approved = false; pend.until = millis() + CONFIRM_WAIT_MS;
  audit("confirm?", p.length() ? a + " " + p : a);
  web.send(200, "text/plain", "pending");
}
// Debounced press (released -> pressed) of the BOOT button.
static int btnStable = HIGH, btnLast = HIGH;
static uint32_t btnT = 0;
static bool bootPressed() {
  int v = digitalRead(BOOT_PIN); uint32_t now = millis();
  if (v != btnLast) { btnLast = v; btnT = now; return false; }
  if (v != btnStable && now - btnT > 40) { btnStable = v; return v == LOW; }
  return false;
}
static void confirmLoop() {
  bool pressed = bootPressed();
  if (pend.action[0] && !confirmActive()) {      // ran out: waiting, or approved but unused
    auditIp(0, "expired", pend.action); pend.action[0] = 0;
  }
  bool waiting = pend.action[0] && !pend.approved;
  if (pressed) {
    if (waiting) {
      pend.approved = true; pend.until = millis() + CONFIRM_USE_MS;
      auditIp(0, "BOOT pressed", String("approved ") + pend.action + " for " + IPAddress(pend.ip).toString());
      waiting = false;
    } else {
      if (clearAllLockouts()) auditIp(0, "BOOT pressed", "login lockouts cleared");
      if (physConfirm && otaHashHex.length()) {
        otaWindowUntil = millis() + OTA_WINDOW_MS;
        auditIp(0, "BOOT pressed", "network OTA open for 60 s");
      }
    }
  }
  ledSet(waiting ? (millis() / 150) & 1 : otaWindowOpen() ? (millis() / 600) & 1 : false);
}
// ---------- pause ----------
// Pausing turns blocking off for the whole network, so with physical confirmation on it's
// limited too: PAUSE_FREE_S of pausing per hour needs only the password; anything longer,
// or indefinite, needs a BOOT press. Without this, one call from an agent with the password
// (or one repeated every few minutes) turns the blocker off for good. Resuming early doesn't
// give the unused time back.
static const uint32_t PAUSE_FREE_S = 900, PAUSE_WINDOW_MS = 3600000, PAUSE_MAX_S = 7 * 86400;
static uint32_t pauseWinStart = 0, pauseFreeUsed = 0;   // pauseWinStart 0: no window open
static uint32_t pauseFreeLeft() {
  if (pauseWinStart && millis() - pauseWinStart >= PAUSE_WINDOW_MS) pauseWinStart = pauseFreeUsed = 0;
  return PAUSE_FREE_S - pauseFreeUsed;
}
static void handlePause() {                      // /pause?s=300  (0 or absent = indefinite)
  if (!requireAuth()) return;
  long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
  if (s < 0) s = 0;
  if (s > (long)PAUSE_MAX_S) s = PAUSE_MAX_S;    // also keeps resumeAt within millis() range
  bool inBudget = physConfirm && s > 0 && (uint32_t)s <= pauseFreeLeft();
  if (physConfirm && !inBudget && !requireConfirm("pause", String(s))) return;
  if (inBudget) { if (!pauseWinStart) pauseWinStart = millis() | 1; pauseFreeUsed += s; }
  blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
  if (s > 0 && !resumeAt) resumeAt = 1;          // 0 means "indefinite"; don't land on it by wraparound
  audit("pause", s > 0 ? String(s) + " s" : String("indefinitely"));
  web.send(200, "text/plain", "paused");
}
// Anyone on the LAN can see the summary (totals, uptime, blocking on/off, whether a password
// is set). Who is on the network (IPs, MACs, per-client counts), the custom list, the update
// URL, lockouts, pending approvals and the audit log only go to a logged-in admin.
static void handleStats() {
  AuthResult r = checkAuth();
  if (r == AUTH_HOST) { sendAuthError(r); return; }
  // Wrong stored credentials (e.g. after a BOOT reset): ask again rather than answering with
  // the summary, so the browser drops them instead of resending them on every poll.
  if (r == AUTH_PROMPT && web.hasHeader("Authorization")) { web.requestAuthentication(); return; }
  bool admin = r == AUTH_OK;
  StateLock lock;
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed + ",\"foreign\":" + totalForeign +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt && (int32_t)(resumeAt - millis()) > 0 ? (resumeAt - millis()) / 1000 : 0) +
             ",\"noauth\":" + (adminSet ? "false" : "true") +
             ",\"upstream\":\"" + jesc(String((const char*)upstreamStatus)) + "\"" +
             ",\"nclients\":" + numClients + ",\"globalLock\":" + String(globalLockedFor()) +
             ",\"locked\":" + String(r == AUTH_LOCKED ? max(lockedFor(clientIp()), globalLockedFor()) : 0) +
             ",\"admin\":" + (admin ? "true" : "false");
  if (!admin) { web.send(200, "application/json", j + "}"); return; }
  j += ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
       ",\"phys\":" + (physConfirm ? "true" : "false") + ",\"otaWin\":" + (otaWindowOpen() ? (otaWindowUntil - millis()) / 1000 + 1 : 0) +
       ",\"pauseFree\":" + pauseFreeLeft() + ",\"you\":\"" + IPAddress(clientIp()).toString() + "\"";
  if (confirmActive()) {
    char ph[9]; snprintf(ph, sizeof(ph), "%08x", (unsigned)pend.ph);
    j += ",\"confirm\":{\"a\":\"" + String(pend.action) + "\",\"p\":\"" + jesc(pend.detail) + "\",\"ph\":\"" + ph +
         "\",\"ip\":\"" + IPAddress(pend.ip).toString() +
         "\",\"state\":\"" + (pend.approved ? "approved" : "pending") + "\",\"left\":" + ((pend.until - millis()) / 1000 + 1) + "}";
  }
  j += ",\"lockouts\":[";
  bool first = true;
  for (int i = 0; i < LOCK_SLOTS; i++) {
    LockEntry& e = locks[i];
    if (!e.fails) continue;
    uint8_t mac[6]; getMac(e.ip, mac);
    j += (first ? "" : ","); first = false;
    j += "{\"ip\":\"" + IPAddress(e.ip).toString() + "\",\"mac\":\"" + macStr(mac) + "\",\"fails\":" + e.fails +
         ",\"lockedFor\":" + lockRemainingS(&e) + "}";
  }
  j += "],\"audit\":[";
  for (int k = 0; k < auditCount; k++) {                 // newest first
    const AuditEntry& e = auditLog[(auditHead - 1 - k + AUDIT_SIZE) % AUDIT_SIZE];
    j += (k ? "," : "");
    j += "{\"ago\":" + String((millis() - e.ms) / 1000) + ",\"ip\":\"" + (e.ip ? IPAddress(e.ip).toString() : String("device")) +
         "\",\"mac\":\"" + (e.ip ? macStr(e.mac) : String("")) + "\",\"what\":\"" + jesc(e.what) + "\",\"detail\":\"" + jesc(e.detail) + "\"}";
  }
  j += "],\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (isBanned(c.ip, c.mac)?"true":"false") + "}"; }
  for (int b = 0; b < numBanned; b++) {                  // banned but not in the table (yet): still listed, so it can be unbanned
    bool listed = false;
    for (int i = 0; i < numClients; i++) if (banMatches(bans[b], clients[i].ip, clients[i].mac)) { listed = true; break; }
    if (listed) continue;
    j += (numClients || b ? "," : ""); j += "{\"ip\":\"" + IPAddress(bans[b].ip).toString() + "\",\"mac\":\"" + macStr(bans[b].mac) + "\",\"blocked\":0,\"allowed\":0,\"banned\":true}";
  }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "],\"allow\":[";
  for (int i = 0; i < numAllow; i++) { j += (i ? "," : ""); j += "\"" + jesc(allowDom[i]) + "\""; }
  j += "]}";
  web.send(200, "application/json", j);
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip;
  if (ip.fromString(web.arg("ip"))) {
    // The dashboard sends the MAC it shows; otherwise use the client table, then ARP.
    uint8_t mac[6] = {};
    bool banned, ok;
    {
      StateLock lock;
      if (!parseMac(web.arg("mac"), mac) || !macKnown(mac)) {
        memset(mac, 0, 6);
        for (int i = 0; i < numClients; i++) if (clients[i].ip == (uint32_t)ip) memcpy(mac, clients[i].mac, 6);
        if (!macKnown(mac)) getMac((uint32_t)ip, mac);
      }
      banned = !isBanned((uint32_t)ip, mac); ok = setBanned((uint32_t)ip, mac, banned);
    }
    if (!ok) { web.send(507, "text/plain", "ban list is full (" + String(MAX_BAN) + " devices): unban one first"); return; }
    audit(banned ? "ban" : "unban", ip.toString() + (macKnown(mac) ? " " + macStr(mac) : String(" (by IP)")));
  }
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The new list is written to /blocklist.new and only replaces the live one after it
// validates. If both fit in the partition at once (the default ~0.5 MB list does), the old
// list keeps blocking during the download and survives a failed one. A list too big to sit
// next to the old one forces delete-first: while that swap runs numHashes=0, so the device
// fail-opens (forwards, no blocking), and a failure leaves it with no list until the next
// good one. The dashboard shows "0 domains" and the status says so.
static const char* NEW_PATH = "/blocklist.new";
static const size_t FS_SLACK = 16384;               // LittleFS metadata/block rounding margin
static void reopenBlocklist() {
  StateLock lock;
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildFlashIndex();
}
static size_t fsFree() { return LittleFS.totalBytes() - LittleFS.usedBytes(); }
// incoming = expected size in bytes, 0 if unknown. Returns true if the old list was kept.
static bool beginBlocklistSwap(size_t incoming) {
  StateLock lock;
  LittleFS.remove(NEW_PATH);
  bool keep = blocklist && numHashes && incoming && incoming + FS_SLACK <= fsFree();
  if (!keep) {
    if (blocklist) blocklist.close();
    numHashes = 0;
    LittleFS.remove(BLOCKLIST_PATH);
  }
  Serial.printf("[blocklist] swap: %s old list (incoming %u B, free %u B)\n",
                keep ? "keeping" : "dropped", (unsigned)incoming, (unsigned)fsFree());
  return keep;
}
static void abortNewBlocklist() {
  StateLock lock;
  LittleFS.remove(NEW_PATH);
  if (!blocklist) reopenBlocklist();                // no-op if the old list was dropped
}
// What the firmware's lookup relies on: whole 5-byte entries, strictly ascending (binary
// search), and, when the sender declared a size, exactly that many bytes (a cut-off
// download used to pass if it happened to stop on a 5-byte boundary).
static bool validBlocklist(size_t expect, String& why) {
  File f = LittleFS.open(NEW_PATH, "r");
  if (!f) { why = "no data written"; return false; }
  size_t sz = f.size();
  if (!sz || sz % HASH_BYTES) { f.close(); why = "size " + String(sz) + " B is not a whole number of entries"; return false; }
  if (expect && sz != expect) { f.close(); why = "truncated: got " + String(sz) + " of " + String(expect) + " B"; return false; }
  uint8_t chunk[HASH_BYTES * 200]; uint64_t prev = 0; size_t seen = 0;
  while (seen < sz) {
    int n = f.read(chunk, sizeof(chunk));
    if (n <= 0 || n % HASH_BYTES) { f.close(); why = "read error"; return false; }
    for (int i = 0; i < n; i += HASH_BYTES) {
      uint64_t v = unpackHash(chunk + i);
      if (seen + i && v <= prev) { f.close(); why = "not sorted (not a blocklist.bin?)"; return false; }
      prev = v;
    }
    seen += n;
  }
  f.close();
  return true;
}
// Validate /blocklist.new and make it live. On failure the new file is discarded and the
// old list, if it was kept, stays live.
static bool commitNewBlocklist(size_t expect, String& why) {
  if (!validBlocklist(expect, why)) { abortNewBlocklist(); return false; }   // reads the new file only: no lock needed
  StateLock lock;
  if (blocklist) blocklist.close();
  numHashes = 0;
  LittleFS.remove(BLOCKLIST_PATH);
  bool ok = LittleFS.rename(NEW_PATH, BLOCKLIST_PATH);
  if (!ok) why = "rename failed";
  reopenBlocklist();
  return ok;
}
static String swapResult(bool ok, const String& why) {
  if (ok) return "ok: " + String(numHashes) + " domains";
  return "rejected: " + why + (numHashes ? " (previous list kept)" : " (NO BLOCKLIST LOADED, blocking is off)");
}

// ---------- OTA blocklist update (browser upload) ----------
// The upload callback runs (and checks auth) before the request's own handler, which
// reports the outcome. AUTH_UNSET = no file part arrived, so nothing was checked yet.
static const int AUTH_UNSET = -1;
static int upAuth = AUTH_UNSET;
static bool upWriteOk = false;
static String upResult;
static File upFile;
static void handleUploadDone() {
  int r = upAuth; upAuth = AUTH_UNSET;               // never carries over to a later request
  if (r == AUTH_UNSET) { if (requireAuth()) web.send(400, "text/plain", "no file received"); return; }
  if (r != AUTH_OK) { sendAuthError((AuthResult)r); return; }
  audit("upload", upResult);
  web.send(upResult.startsWith("ok") ? 200 : 500, "text/plain", upResult);
}
// Auth + physical confirmation for an upload, checked when its first part arrives. That
// the file is the approved one is checked at its end (gateOk()).
static int uploadAuth(const char* action) {
  AuthResult r = checkAuth();
  if (r == AUTH_OK && !gateStart(action)) { audit("unconfirmed", action); r = AUTH_CONFIRM; }
  return r;
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuth = uploadAuth("upload");
      if (upAuth != AUTH_OK) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      // The request body is the file plus a few hundred bytes of multipart framing, so it
      // slightly overestimates the file: errs toward dropping the old list, never toward
      // running out of space with it kept.
      beginBlocklistSwap(web.clientContentLength() > 0 ? (size_t)web.clientContentLength() : 0);
      upFile = LittleFS.open(NEW_PATH, "w");
      upWriteOk = (bool)upFile;
      upResult = "rejected: upload interrupted";
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuth != AUTH_OK) break;
      gateWrite(u.buf, u.currentSize);
      if (upFile && upWriteOk && upFile.write(u.buf, u.currentSize) != u.currentSize) upWriteOk = false;
      break;
    case UPLOAD_FILE_END: {
      if (upAuth != AUTH_OK) break;
      if (upFile) upFile.close();
      String why = "write failed (flash full?)"; bool ok = false;
      if (upWriteOk && !gateOk()) { upWriteOk = false; why = "not the file approved with BOOT"; audit("wrong file", "blocklist"); }
      if (upWriteOk) ok = commitNewBlocklist(0, why);
      else abortNewBlocklist();
      upResult = swapResult(ok, why);
      Serial.printf("[ota] %s\n", upResult.c_str());
      break;
    }
    case UPLOAD_FILE_ABORTED:
      if (upAuth != AUTH_OK) break;
      if (upFile) upFile.close();
      abortNewBlocklist();
      upResult = swapResult(false, "upload aborted");
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim();
  long h = iv.length() ? iv.toInt() : 24;
  f.close(); updateIntervalH = (uint32_t)constrain(h, (long)UPDATE_MIN_H, (long)UPDATE_MAX_H);
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
// HTTPS only, with the server certificate checked against the small root bundle in
// ca_bundle.h (tools/gen_ca_bundle.py). This used to be setInsecure() and also allowed
// plain http, so anyone on the network path could swap in their own list: one that blocks
// nothing, or one that blocks sites of their choosing.
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  if (!url.startsWith("https://")) { updateStatus = "rejected: URL must start with https://"; return false; }
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs; cs.setCACertBundle(CA_BUNDLE);
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  if (!http.begin(cs, url)) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    char tls[96] = ""; cs.lastError(tls, sizeof(tls));
    http.end();
    updateStatus = code < 0 ? "failed: " + HTTPClient::errorToString(code) + (*tls ? " (" + String(tls) + ")" : "")
                            : "HTTP " + String(code);
    Serial.printf("[remote] %s\n", updateStatus.c_str());
    return false;
  }
  int len = http.getSize();                         // -1 if the server didn't say (chunked)
  if (len > 0 && (size_t)len + FS_SLACK > LittleFS.totalBytes()) {
    http.end(); updateStatus = "rejected: " + String(len) + " B is larger than the blocklist partition";
    return false;
  }
  beginBlocklistSwap(len > 0 ? (size_t)len : 0);
  File f = LittleFS.open(NEW_PATH, "w");
  if (!f) { http.end(); abortNewBlocklist(); updateStatus = swapResult(false, "fs open failed"); return false; }
  int n = http.writeToStream(&f);                   // decodes chunked; < 0 on error or short write
  f.close(); http.end();
  String why; bool ok = false;
  if (n < 0) { why = "download failed: " + HTTPClient::errorToString(n); abortNewBlocklist(); }
  else ok = commitNewBlocklist(len > 0 ? (size_t)len : 0, why);
  updateStatus = swapResult(ok, why);
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static int fwAuth = AUTH_UNSET;
static bool fwWrongFile = false;
static void handleFwUpdateDone() {
  int r = fwAuth; fwAuth = AUTH_UNSET;
  bool wrong = fwWrongFile; fwWrongFile = false;
  if (r == AUTH_UNSET) { if (requireAuth()) web.send(400, "text/plain", "no file received"); return; }
  if (r != AUTH_OK) { sendAuthError((AuthResult)r); return; }
  if (wrong) { web.send(428, "text/plain", "rejected: not the file approved with BOOT (nothing was flashed)"); return; }
  bool ok = !Update.hasError();
  audit("firmware", ok ? "flashed, rebooting" : "update failed");
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuth = uploadAuth("update"); fwWrongFile = false;
    if (fwAuth != AUTH_OK) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (fwAuth != AUTH_OK) return;
    gateWrite(u.buf, u.currentSize);
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (fwAuth != AUTH_OK) return;
    if (!gateOk()) { Update.abort(); fwWrongFile = true; audit("wrong file", "firmware"); Serial.println("[fw-ota] not the approved file, aborted"); }
    else if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (fwAuth != AUTH_OK) return;
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- HTTPS ----------
// The dashboard is served over TLS, so the admin password (Basic Auth) and everything else
// stay encrypted on the LAN. The certificate is self-signed: browsers warn once, and the
// SHA-256 fingerprint printed on the serial console and shown on the setup page lets you
// check it's this device before accepting. The key (ECDSA P-256) and certificate are made
// on the device on first boot and kept in NVS ("tls"), so the fingerprint stays the same
// across reboots, firmware updates and BOOT resets.
//
// tlsTask terminates TLS on :443 and relays each request, one connection at a time, to the
// WebServer on 127.0.0.1:INNER_PORT. It adds X-C3-Peer (see clientIp) and Connection:
// close, so each TLS connection carries exactly one request; the session cache makes the
// repeat handshakes cheap. It runs in its own task because WebServer reads a whole upload
// inside one handleClient() call, which would deadlock with a relay in the same loop.
static mbedtls_x509_crt   tlsCert;
static mbedtls_pk_context tlsKey;
static mbedtls_ssl_config tlsConf;
static mbedtls_ssl_cache_context tlsCache;
static String tlsFingerprint;                       // "AB:CD:..." SHA-256 of the certificate

static bool makeTlsCert(uint8_t* keyDer, size_t& keyLen, uint8_t* crtDer, size_t& crtLen) {
  static const char NAME[] = "CN=c3adblock.local,O=C3 AdBlock";
  // subjectAltName: dNSName c3adblock.local, dNSName c3adblock
  static const uint8_t SAN[] = { 0x30, 0x1c, 0x82, 0x0f, 'c','3','a','d','b','l','o','c','k','.','l','o','c','a','l',
                                 0x82, 0x09, 'c','3','a','d','b','l','o','c','k' };
  static uint8_t buf[1024];
  mbedtls_pk_context pk; mbedtls_pk_init(&pk);
  mbedtls_x509write_cert crt; mbedtls_x509write_crt_init(&crt);
  mbedtls_mpi serial; mbedtls_mpi_init(&serial);
  uint8_t sn[16]; esp_fill_random(sn, sizeof(sn)); sn[0] &= 0x7f;   // positive serial
  bool ok = false;
  do {
    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) break;
    if (mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk), hwRng, nullptr)) break;
    if (mbedtls_mpi_read_binary(&serial, sn, sizeof(sn))) break;
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt, &pk);
    mbedtls_x509write_crt_set_issuer_key(&crt, &pk);
    if (mbedtls_x509write_crt_set_serial(&crt, &serial)) break;
    if (mbedtls_x509write_crt_set_subject_name(&crt, NAME) || mbedtls_x509write_crt_set_issuer_name(&crt, NAME)) break;
    if (mbedtls_x509write_crt_set_validity(&crt, "20250101000000", "20991231235959")) break;   // no RTC: fixed range
    if (mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1)) break;
    if (mbedtls_x509write_crt_set_extension(&crt, MBEDTLS_OID_SUBJECT_ALT_NAME, MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
                                            0, SAN, sizeof(SAN))) break;
    int n = mbedtls_x509write_crt_der(&crt, buf, sizeof(buf), hwRng, nullptr);   // written at the END of buf
    if (n <= 0 || (size_t)n > crtLen) break;
    memcpy(crtDer, buf + sizeof(buf) - n, n); crtLen = n;
    n = mbedtls_pk_write_key_der(&pk, buf, sizeof(buf));
    if (n <= 0 || (size_t)n > keyLen) break;
    memcpy(keyDer, buf + sizeof(buf) - n, n); keyLen = n;
    ok = true;
  } while (false);
  memset(buf, 0, sizeof(buf));
  mbedtls_mpi_free(&serial); mbedtls_x509write_crt_free(&crt); mbedtls_pk_free(&pk);
  return ok;
}
static bool parseTlsCert(const uint8_t* key, size_t keyLen, const uint8_t* crt, size_t crtLen) {
  mbedtls_x509_crt_free(&tlsCert); mbedtls_pk_free(&tlsKey);
  mbedtls_x509_crt_init(&tlsCert); mbedtls_pk_init(&tlsKey);
  return keyLen && crtLen && !mbedtls_x509_crt_parse_der(&tlsCert, crt, crtLen) &&
         !mbedtls_pk_parse_key(&tlsKey, key, keyLen, nullptr, 0);
}
// Call with the radio on: the hardware RNG is only truly random while WiFi is running.
static bool loadTlsCert() {
  uint8_t key[200], crt[800];
  prefs.begin("tls", true);
  size_t keyLen = prefs.isKey("key") ? prefs.getBytes("key", key, sizeof(key)) : 0;
  size_t crtLen = prefs.isKey("crt") ? prefs.getBytes("crt", crt, sizeof(crt)) : 0;
  prefs.end();
  bool ok = parseTlsCert(key, keyLen, crt, crtLen);
  if (!ok) {
    Serial.println("[https] creating this device's TLS key and certificate...");
    keyLen = sizeof(key); crtLen = sizeof(crt);
    ok = makeTlsCert(key, keyLen, crt, crtLen) && parseTlsCert(key, keyLen, crt, crtLen);
    if (ok) { prefs.begin("tls", false); prefs.putBytes("key", key, keyLen); prefs.putBytes("crt", crt, crtLen); prefs.end(); }
  }
  memset(key, 0, sizeof(key));
  if (!ok) { Serial.println("[https] FAILED to set up the TLS certificate"); return false; }
  uint8_t h[32]; char hex[4];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), crt, crtLen, h);
  tlsFingerprint = "";
  for (int i = 0; i < 32; i++) { snprintf(hex, sizeof(hex), i ? ":%02X" : "%02X", h[i]); tlsFingerprint += hex; }
  return true;
}

static int tlsSend(void* ctx, const unsigned char* b, size_t n) {
  int r = send(*(int*)ctx, b, n, 0);
  return r >= 0 ? r : (errno == EAGAIN || errno == EWOULDBLOCK) ? MBEDTLS_ERR_SSL_TIMEOUT : MBEDTLS_ERR_NET_SEND_FAILED;
}
static int tlsRecv(void* ctx, unsigned char* b, size_t n) {
  int r = recv(*(int*)ctx, b, n, 0);
  return r >= 0 ? r : (errno == EAGAIN || errno == EWOULDBLOCK) ? MBEDTLS_ERR_SSL_TIMEOUT : MBEDTLS_ERR_NET_RECV_FAILED;
}
static bool tlsWriteAll(mbedtls_ssl_context* ssl, const uint8_t* p, size_t n) {
  while (n) {
    int r = mbedtls_ssl_write(ssl, p, n);
    if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
    if (r <= 0) return false;
    p += r; n -= r;
  }
  return true;
}
static bool sendAll(int fd, const uint8_t* p, size_t n) {
  while (n) { int r = send(fd, p, n, 0); if (r <= 0) return false; p += r; n -= r; }
  return true;
}
// A failed TLS setup or handshake leaves the browser with just a reset connection, so say
// why on the console, with the memory situation (each TLS session needs ~35 KB in one piece).
// Browsers abort a handshake on purpose until the certificate is accepted, so this is
// rate-limited rather than silenced.
static void tlsFailNote(const char* what, int r) {
  static uint32_t last = 0;
  if (last && millis() - last < 10000) return;
  last = millis() | 1;
  char e[96]; mbedtls_strerror(r, e, sizeof(e));
  Serial.printf("[https] TLS %s failed: -0x%04x %s (free heap %u, largest block %u)\n", what, (unsigned)-r, e,
                (unsigned)ESP.getFreeHeap(), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
}
// One TLS connection: handshake, read the request head, rewrite it, relay to the dashboard.
static void tlsServe(int fd, uint32_t peer) {
  static const size_t HEAD_MAX = 4096;
  static char head[HEAD_MAX + 1], out[HEAD_MAX + 160];   // tlsTask only
  static uint8_t buf[1460];
  mbedtls_ssl_context ssl; mbedtls_ssl_init(&ssl);
  int in = -1, r;
  do {
    relayAt(1);
    if ((r = mbedtls_ssl_setup(&ssl, &tlsConf))) { tlsFailNote("setup", r); break; }   // usually out of memory
    mbedtls_ssl_set_bio(&ssl, &fd, tlsSend, tlsRecv, nullptr);
    while ((r = mbedtls_ssl_handshake(&ssl)) == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {}
    if (r) { tlsFailNote("handshake", r); break; }  // e.g. the browser refusing the certificate until it's accepted
    relayAt(2);
    size_t len = 0; int end = -1;
    while (end < 0 && len < HEAD_MAX) {
      r = mbedtls_ssl_read(&ssl, (uint8_t*)head + len, HEAD_MAX - len);
      if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
      if (r <= 0) break;
      len += r; head[len] = 0;
      const char* e = strstr(head, "\r\n\r\n");
      if (e) end = e - head + 4;
    }
    if (end < 0) {
      if (len >= HEAD_MAX) {
        static const char TOO_BIG[] = "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        tlsWriteAll(&ssl, (const uint8_t*)TOO_BIG, sizeof(TOO_BIG) - 1);
      }
      break;
    }
    // Request line, then our headers, then the browser's minus any X-C3-Peer / Connection.
    const char* first = strstr(head, "\r\n");
    size_t o = first - head + 2;
    memcpy(out, head, o);
    o += snprintf(out + o, sizeof(out) - o, "%s: %s %s\r\nConnection: close\r\n",
                  PEER_HEADER, IPAddress(peer).toString().c_str(), peerToken);
    for (const char* l = head + (first - head + 2); l < head + end - 2; ) {
      const char* le = strstr(l, "\r\n");
      size_t ll = le - l + 2;
      if (strncasecmp(l, "X-C3-Peer:", 10) && strncasecmp(l, "Connection:", 11)) { memcpy(out + o, l, ll); o += ll; }
      l += ll;
    }
    memcpy(out + o, "\r\n", 2); o += 2;

    relayAt(3);
    in = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a = {}; a.sin_family = AF_INET; a.sin_port = htons(INNER_PORT); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (in < 0 || connect(in, (sockaddr*)&a, sizeof(a))) break;
    // Both directions time out: a send that blocks forever (the dashboard not reading while
    // it waits to write its own reply) would wedge this task, and with it every HTTPS request.
    timeval tv = { 30, 0 }; setsockopt(in, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    timeval sv = { 10, 0 }; setsockopt(in, SOL_SOCKET, SO_SNDTIMEO, &sv, sizeof(sv));
    relayAt(4);
    if (!sendAll(in, (const uint8_t*)out, o) || ((size_t)end < len && !sendAll(in, (const uint8_t*)head + end, len - end))) break;

    relayAt(5);
    // Relay both ways until the dashboard closes its side (it always does: Connection: close).
    bool browserOpen = true; uint32_t idle = millis();
    for (;;) {
      bool buffered = browserOpen && mbedtls_ssl_get_bytes_avail(&ssl) > 0;
      fd_set rf; FD_ZERO(&rf); FD_SET(in, &rf); if (browserOpen) FD_SET(fd, &rf);
      timeval t = { 0, 200000 };
      int s = buffered ? 1 : select(max(fd, in) + 1, &rf, nullptr, nullptr, &t);
      if (s < 0) break;
      if (s == 0) { if (millis() - idle > 30000) break; continue; }
      if (buffered || FD_ISSET(fd, &rf)) {          // browser -> dashboard (request body)
        r = mbedtls_ssl_read(&ssl, buf, sizeof(buf));
        if (r > 0) { if (!sendAll(in, buf, r)) break; idle = millis(); }
        else if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE) { browserOpen = false; shutdown(in, SHUT_WR); }
      }
      if (!buffered && FD_ISSET(in, &rf)) {         // dashboard -> browser
        r = recv(in, buf, sizeof(buf), 0);
        if (r <= 0) break;                          // response complete
        if (!tlsWriteAll(&ssl, buf, r)) break;
        idle = millis();
      }
    }
    relayAt(6);
    mbedtls_ssl_close_notify(&ssl);
  } while (false);
  if (in >= 0) close(in);
  mbedtls_ssl_free(&ssl);
}
static void tlsTask(void* arg) {
  int ls = (int)(intptr_t)arg;
  for (;;) {
    sockaddr_in from; socklen_t fl = sizeof(from);
    int fd = accept(ls, (sockaddr*)&from, &fl);
    if (fd < 0) { delay(100); continue; }
    timeval tv = { 10, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    tlsServe(fd, from.sin_addr.s_addr);
    close(fd);
    relayAt(0);
  }
}
static bool startHttps() {
  uint8_t t[16]; esp_fill_random(t, sizeof(t));
  for (int i = 0; i < 16; i++) snprintf(peerToken + 2 * i, 3, "%02x", t[i]);
  mbedtls_ssl_config_init(&tlsConf);
  if (mbedtls_ssl_config_defaults(&tlsConf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) return false;
  mbedtls_ssl_conf_rng(&tlsConf, hwRng, nullptr);
  if (mbedtls_ssl_conf_own_cert(&tlsConf, &tlsCert, &tlsKey)) return false;
  mbedtls_ssl_cache_init(&tlsCache); mbedtls_ssl_cache_set_max_entries(&tlsCache, 8);
  mbedtls_ssl_conf_session_cache(&tlsConf, &tlsCache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
  int ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), one = 1;
  if (ls < 0) return false;
  setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in a = {}; a.sin_family = AF_INET; a.sin_port = htons(443); a.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(ls, (sockaddr*)&a, sizeof(a)) || listen(ls, 4)) { close(ls); return false; }
  // Stack: the ECDHE/ECDSA handshake needs a few KB of mbedtls stack on top of the relay.
  return xTaskCreate(tlsTask, "https", 10240, (void*)(intptr_t)ls, 2, nullptr) == pdPASS;
}
// :80 only redirects to https, to the same name if it's one of ours, else to our IP.
static void handleRedirect() {
  WiFiClient c = httpRedirect.available();
  if (!c) return;
  c.setTimeout(1);
  String host; uint32_t t0 = millis();
  while (c.connected() && millis() - t0 < 1000) {
    if (!c.available()) { delay(1); continue; }
    String l = c.readStringUntil('\n'); l.trim();
    if (!l.length()) break;
    if (l.length() > 5 && l.substring(0, 5).equalsIgnoreCase("host:")) { host = l.substring(5); host.trim(); }
  }
  host.toLowerCase();
  int colon = host.indexOf(':'); if (colon >= 0) host.remove(colon);
  if (host.endsWith(".")) host.remove(host.length() - 1);
  if (host != "c3adblock.local" && host != "c3adblock") host = WiFi.localIP().toString();
  c.print("HTTP/1.1 301 Moved Permanently\r\nLocation: https://" + host + "/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
  c.stop();
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  prefs.begin("wifi", true); bool nvs = prefs.getString("ssid", "").length() > 0; prefs.end();
  return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static bool portalNeedsPass() { return adminSet && !portalRecovery; }

// Once joined, swap a stored WPA/WPA2 passphrase for the key derived from it (PMK =
// PBKDF2-HMAC-SHA1(passphrase, SSID, 4096), 64 hex digits, which ESP-IDF accepts in place of
// the passphrase). The key still joins this network, but the passphrase, often reused for
// other things, is no longer on the device. WPA3 needs the passphrase itself (SAE), so
// WPA3-only and mixed WPA2/WPA3 networks keep it: on a mixed network the chip joins with
// SAE, and handed the 64-hex key it uses it as the SAE password, so every later join failed
// and the device fell back into setup mode. Only NVS credentials are touched, never secrets.h.
static void protectWifiPass() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", ""), pw = prefs.getString("pass", "");
  prefs.end();
  if (!ss.length() || pw.length() < 8 || pw.length() > 63 || WiFi.SSID() != ss) return;   // none, open, already a key
  wifi_ap_record_t ap;
  if (esp_wifi_sta_get_ap_info(&ap) != ESP_OK) return;
  if (ap.authmode != WIFI_AUTH_WPA_PSK && ap.authmode != WIFI_AUTH_WPA2_PSK &&
      ap.authmode != WIFI_AUTH_WPA_WPA2_PSK) return;
  uint8_t pmk[32];
  if (!pbkdf2(MBEDTLS_MD_SHA1, (const uint8_t*)pw.c_str(), pw.length(), (const uint8_t*)ss.c_str(), ss.length(), 4096, pmk, 32)) return;
  char hex[65];
  for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02x", pmk[i]);
  prefs.begin("wifi", false); prefs.putString("pass", hex); prefs.end();
  Serial.println("[wifi] stored passphrase replaced with its derived key (PMK)");
}

// The setup AP is WPA2, so the WiFi and admin passwords typed into the setup page aren't
// sent in the clear. Its password is random, made on first boot and kept in NVS ("setup",
// which BOOT reset leaves alone) so it never changes. It's printed on the serial console at
// every boot and every 15 s while the portal is open: the web flasher's "Logs & Console",
// or `pio device monitor`.
static String setupPass;
static String setupApName() {
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  return ap;
}
static void loadSetupPass() {                  // call with the radio on (hardware RNG)
  prefs.begin("setup", false);
  setupPass = prefs.getString("appass", "");
  if (setupPass.length() < 8) {
    static const char A[] = "abcdefghjkmnpqrstuvwxyz23456789";   // no 0/o, 1/l/i
    char p[15];
    for (int i = 0; i < 14; i++) p[i] = (i % 5 == 4) ? '-' : A[esp_random() % (sizeof(A) - 1)];
    p[14] = 0;
    setupPass = p; prefs.putString("appass", setupPass);
  }
  prefs.end();
}
static String tlsNote() {
  if (!tlsFingerprint.length()) return "";
  return "<p style='color:#8b949e;font-size:13px;margin-top:22px'>Afterwards the dashboard is at <b>https://c3adblock.local</b>. "
         "Your browser will warn that the certificate isn't trusted: it's this device's own. Check that its SHA-256 "
         "fingerprint is<br><code style='word-break:break-all'>" + tlsFingerprint + "</code><br>before you continue.</p>";
}

static void handlePortalRoot() {
  String cur = portalNeedsPass()
    ? String("<p style='color:#8b949e;margin:18px 0 0'>Current dashboard admin password (forgot it? hold <b>BOOT</b> while powering on):</p>"
             "<input name=c type=password required autocomplete=current-password placeholder='Current admin password' "
             "style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>")
    : String("");
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>C3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; C3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave>"
    "<input list=nets name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>" +
    cur +
    "<p style='color:#8b949e;margin:18px 0 0'>" +
    (adminSet
      ? String("New dashboard admin password (leave blank to keep the current one):")
      : "Choose a dashboard admin password (8+ characters). It protects firmware updates and settings; user name is <b>" + htmlEscape(WEB_USER) + "</b>.") +
    "</p><input name=a type=password minlength=8 " + String(adminSet ? "" : "required ") +
    "autocomplete=new-password placeholder='Admin password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form>" + tlsNote() + "</body>";
  portalWeb.send(200, "text/html", html);
}
// Save WiFi + admin password from the setup page or from USB (PROVISION, below), with the
// same rules for both: a configured device needs its current admin password unless BOOT was
// held at power-on. Returns an HTTP status; on anything but 200, err says why.
static int saveProvision(const String& ss, const String& pw, const String& ap, const String& cur, String& err) {
  if (!ss.length() || ss.length() > 32) { err = "WiFi name must be 1 to 32 bytes"; return 400; }
  if (pw.length() && (pw.length() < 8 || pw.length() > 64)) { err = "WiFi password must be 8 to 63 characters (or empty for an open network)"; return 400; }
  if (portalNeedsPass()) {
    if (portalFails >= PORTAL_MAX_FAILS) {
      err = "too many wrong passwords: power-cycle the device, or hold BOOT while powering on to reset it"; return 429;
    }
    if (!verifyAdminPass(cur)) {
      portalFails++;
      Serial.printf("[setup] wrong current admin password (%u/%u)\n", portalFails, PORTAL_MAX_FAILS);
      delay(1000);
      err = "wrong current admin password"; return 403;
    }
  }
  if (ap.length() ? ap.length() < MIN_ADMIN_PASS : !adminSet) { err = "admin password must be at least 8 characters"; return 400; }
  if (ap.length()) setAdminPass(ap, true);
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  return 200;
}
static void handleWifiSave() {
  String ss = portalWeb.arg("s"), err;
  int code = saveProvision(ss, portalWeb.arg("p"), portalWeb.arg("a"), portalWeb.arg("c"), err);
  if (code != 200) { portalWeb.send(code, "text/plain", err); return; }
  portalWeb.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + htmlEscape(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>c3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// ---------- USB serial commands (used by start-here.py) ----------
// Whoever is on the USB port can already reflash the chip or read the setup password the
// console prints, so these give nothing away: they let the setup helper do from the
// computer what the setup page does from a phone. One command per line:
//   INFO                               -> [info] mode=<setup|online> ip=... ap="..." fp=...
//   NETS                               -> [nets] <hex ssid>,<hex ssid>,...   (setup mode only)
//   PROVISION <ssid> <pass> <admin> [<current admin>]   all hex-encoded UTF-8, empty = "-"
//                                      -> [provision] ok   (then restarts and joins)
//                                      -> [provision] error <code> <reason>
static String serialLine;
static String portalNets;                      // scanned SSIDs, hex, comma-separated (for NETS)
static bool inPortal = false;
static String hexDecode(const String& h, bool& ok) {
  String out; ok = true;
  if (h == "-") return out;
  if (h.length() % 2 || h.length() > 256) { ok = false; return out; }
  for (unsigned i = 0; i < h.length(); i += 2) {
    char b[3] = { h[i], h[i + 1], 0 }; char* end;
    long v = strtol(b, &end, 16);
    if (*end || !v) { ok = false; return out; }            // NUL would cut the string short
    out += (char)v;
  }
  return out;
}
static String hexEncode(const String& s) {
  static const char H[] = "0123456789abcdef"; String out;
  for (unsigned i = 0; i < s.length(); i++) { uint8_t c = s[i]; out += H[c >> 4]; out += H[c & 15]; }
  return out;
}
// ---------- health ----------
// A separate task on the app core prints one [health] line: every 2 s after DIAG on, and on
// its own (at most every 10 s) whenever something looks wrong: the HTTPS relay stuck in one
// stage, loop() or the DNS task not running, or memory running out. It keeps working when
// the network side is wedged, which is exactly when the console would otherwise go quiet.
static volatile bool diagOn = false;
static void healthLine(const char* why) {
  uint32_t now = millis();
  Serial.printf("[health] %s up=%lus heap=%u min=%u maxblock=%u loop=%lums dns=%lums relay=%s/%lus wifi=%d rssi=%d\n",
                why, (unsigned long)(now / 1000), (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMinFreeHeap(),
                (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT),
                (unsigned long)(loopBeat ? now - loopBeat : 0), (unsigned long)(dnsBeat ? now - dnsBeat : 0),
                RELAY_STAGES[relayStage < 7 ? relayStage : 0], (unsigned long)((now - relayStageSince) / 1000),
                (int)WiFi.status(), (int)WiFi.RSSI());
}
static void healthTask(void*) {
  uint32_t lastAuto = 0;
  for (;;) {
    delay(2000);
    if (!loopBeat) continue;                                   // still booting
    uint32_t now = millis();
    const char* why = nullptr;
    if (relayStage && now - relayStageSince > 15000) why = "relay-stuck";
    else if (now - loopBeat > 5000) why = "loop-stuck";
    else if (dnsBeat && now - dnsBeat > 5000) why = "dns-stuck";
    else if (heap_caps_get_largest_free_block(MALLOC_CAP_8BIT) < 12000) why = "low-memory";
    if (why && (!lastAuto || now - lastAuto >= 10000)) { lastAuto = now; healthLine(why); }
    else if (diagOn) healthLine("diag");
  }
}
static void startHealth() {
#if CONFIG_FREERTOS_UNICORE
  xTaskCreate(healthTask, "health", 3072, nullptr, 5, nullptr);
#else
  xTaskCreatePinnedToCore(healthTask, "health", 3072, nullptr, 5, nullptr, 1);   // away from WiFi/lwIP on core 0
#endif
}

static void serialCommand(String line) {
  line.trim();
  int sp = line.indexOf(' ');
  String cmd = sp < 0 ? line : line.substring(0, sp);
  String rest = sp < 0 ? String("") : line.substring(sp + 1);
  if (cmd == "INFO") {
    Serial.printf("[info] mode=%s ip=%s ap=\"%s\" fp=%s admin=%s heap=%u maxblock=%u\n", inPortal ? "setup" : "online",
                  inPortal ? "" : WiFi.localIP().toString().c_str(), setupApName().c_str(),
                  tlsFingerprint.c_str(), adminSet ? "set" : "unset",
                  (unsigned)ESP.getFreeHeap(), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
  } else if (cmd == "NETS") {
    if (!inPortal) { Serial.println("[nets] error not in setup mode"); return; }
    Serial.println("[nets] " + portalNets);
  } else if (cmd == "PROVISION") {
    if (!inPortal) { Serial.println("[provision] error 409 already online: hold BOOT while powering on to set it up again"); return; }
    String f[4]; int n = 0;
    while (rest.length() && n < 4) {
      int s2 = rest.indexOf(' ');
      f[n++] = s2 < 0 ? rest : rest.substring(0, s2);
      rest = s2 < 0 ? String("") : rest.substring(s2 + 1);
    }
    if (n < 3) { Serial.println("[provision] error 400 usage: PROVISION <ssid> <pass> <admin> [<current>]"); return; }
    bool ok1, ok2, ok3, ok4;
    String ss = hexDecode(f[0], ok1), pw = hexDecode(f[1], ok2), ap = hexDecode(f[2], ok3), cur = hexDecode(n > 3 ? f[3] : String("-"), ok4);
    if (!(ok1 && ok2 && ok3 && ok4)) { Serial.println("[provision] error 400 fields must be hex"); return; }
    String err; int code = saveProvision(ss, pw, ap, cur, err);
    if (code != 200) { Serial.printf("[provision] error %d %s\n", code, err.c_str()); return; }
    Serial.printf("[provision] ok, restarting to join \"%s\"\n", ss.c_str());
    Serial.flush(); delay(500); ESP.restart();
  } else if (cmd == "DIAG") {
    diagOn = rest != "off";
    Serial.printf("[diag] %s\n", diagOn ? "on: a [health] line every 2 s (DIAG off to stop)" : "off");
    if (diagOn) healthLine("now");
  } else if (cmd.length()) {
    Serial.printf("[cmd] unknown command %s (INFO, NETS, PROVISION, DIAG)\n", cmd.c_str());
  }
}
static void pollSerial() {
  while (Serial.available()) {
    char ch = Serial.read();
    if (ch == '\n' || ch == '\r') { if (serialLine.length()) serialCommand(serialLine); serialLine = ""; }
    else if (serialLine.length() < 800) serialLine += ch;    // longest PROVISION line is ~720
  }
}

// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  inPortal = true;
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
  portalNets = "";
  for (int i = 0; i < n && i < 20; i++) { if (i) portalNets += ","; portalNets += hexEncode(WiFi.SSID(i)); }
  String ap = setupApName();
  WiFi.mode(WIFI_AP); WiFi.softAP(ap.c_str(), setupPass.c_str());
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  portalWeb.on("/", handlePortalRoot);
  portalWeb.on("/wifisave", HTTP_POST, handleWifiSave);
  portalWeb.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  portalWeb.begin();
  Serial.printf("\n[setup] No WiFi. Join \"%s\" (password %s) and a setup page pops up (or http://%s)\n",
                ap.c_str(), setupPass.c_str(), apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis(), shown = millis();
  while (true) {
    dnsPortal.processNextRequest(); portalWeb.handleClient(); pollSerial(); delay(2);
    if (millis() - shown > 15000) {                                // for whoever opens the serial console late
      shown = millis();
      Serial.printf("[setup] setup WiFi \"%s\", password %s\n", ap.c_str(), setupPass.c_str());
    }
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println("\n[c3-adblock] booting");
  stateMutex = xSemaphoreCreateRecursiveMutex();
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) {
    numHashes = blocklist.size() / HASH_BYTES;
    Serial.printf("blocklist: %u domains\n", numHashes);
    buildFlashIndex();
  }
  loadCustom(); loadAllow(); loadBanned(); loadUpdateCfg();
  Serial.printf("custom: %d, exceptions: %d, banned: %d\n", numCustom, numAllow, numBanned);

  // Hold BOOT at power-on to wipe saved WiFi and force the setup portal.
  // Physical access is the recovery path for a forgotten admin password, so this clears it
  // too, and goes straight to the portal even if secrets.h has fallback WiFi creds.
  pinMode(BOOT_PIN, INPUT_PULLUP);
  bool forcePortal = false;
  if (digitalRead(BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(BOOT_PIN) == LOW) {
      prefs.begin("wifi", false); prefs.clear(); prefs.end();
      prefs.begin("auth", false); prefs.clear(); prefs.end();   // also turns physical confirmation back on
      forcePortal = portalRecovery = true;
      Serial.println("[setup] BOOT held -> cleared saved WiFi + admin password"); } }
  loadAuth(); loadPhys();
  WiFi.mode(WIFI_STA);                     // radio on first: the hardware RNG is only truly random with it running
  loadSetupPass();
  bool tlsReady = loadTlsCert();
  Serial.printf("[setup] setup WiFi (if it's ever needed): \"%s\", password %s\n", setupApName().c_str(), setupPass.c_str());
  if (tlsReady) Serial.printf("[https] certificate SHA-256 fingerprint: %s\n", tlsFingerprint.c_str());

  if (forcePortal || !connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  protectWifiPass();
  if (MDNS.begin("c3adblock")) { MDNS.addService("https", "tcp", 443); MDNS.addService("http", "tcp", 80); }

  if (!adminSet)
    Serial.println("[WARN] no admin password set: settings, uploads and OTA are locked. "
                   "Hold BOOT while powering on to run setup and choose one.");

  startHealth();
  if (!startDns()) Serial.println("[dns] FAILED to start");
  { const char* hdrs[] = { CSRF_HEADER, PEER_HEADER }; web.collectHeaders(hdrs, 2); }  // CSRF check + client address
  web.on("/", []() { if (requireHost()) web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/login", []() { if (requireAuth()) web.send(200, "text/plain", "ok"); });   // dashboard's Log in button: triggers the browser prompt
  web.on("/ban", handleBan);
  web.on("/addblock", []() {
    if (!requireAuth()) return;
    String d = web.arg("d"); const char* why;
    { StateLock lock; why = addCustom(d); }
    if (why) { web.send(400, "text/plain", why); return; }
    audit("block domain", d); web.send(200, "text/plain", "ok");
  });
  web.on("/unblock", []() { if (!requireAuth()) return; String d = web.arg("d"); { StateLock lock; removeCustom(d); } audit("unblock domain", d); web.send(200, "text/plain", "ok"); });
  web.on("/allow", []() {                    // /allow?d=<domain>: never block it (or its subdomains)
    if (!requireAuth()) return;
    String d = web.arg("d"); const char* why;
    { StateLock lock; why = addAllow(d); }
    if (why) { web.send(400, "text/plain", why); return; }
    audit("allow domain", d); web.send(200, "text/plain", "ok");
  });
  web.on("/unallow", []() { if (!requireAuth()) return; String d = web.arg("d"); { StateLock lock; removeAllow(d); } audit("remove exception", d); web.send(200, "text/plain", "ok"); });
  web.on("/pause", handlePause);             // /pause?s=300  (0 or absent = indefinite)
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; audit("resume"); web.send(200, "text/plain", "resumed"); });
  web.on("/confirm", handleConfirm);         // /confirm?a=<action>&p=<param>: start waiting for a BOOT press
  web.on("/setphys", []() {                  // /setphys?on=0|1  (turning it off needs a press)
    if (!requireAuth()) return;
    bool on = web.arg("on") != "0";
    if (!on && physConfirm && !requireConfirm("phys")) return;
    physConfirm = on; savePhys(); if (!on) otaWindowUntil = 0;
    audit("physical confirm", on ? "on" : "off");
    web.send(200, "text/plain", "ok");
  });
  web.on("/forgetwifi", []() {
    if (!requireAuth() || !requireConfirm("forgetwifi")) return;
    audit("forget wifi");
    web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() { if (!requireAuth()) return; fetchBlocklist(updateUrl); audit("fetch now", updateStatus); web.send(200, "text/plain", updateStatus); });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    String u = updateUrl;
    if (web.hasArg("u")) {
      u = web.arg("u"); u.trim();
      if (u.length() && !u.startsWith("https://")) { web.send(400, "text/plain", "update URL must start with https://"); return; }
      for (char ch : u) if ((uint8_t)ch <= 0x20 || (uint8_t)ch == 0x7f) {   // /update.cfg is line-based
        web.send(400, "text/plain", "update URL must not contain spaces or control characters"); return;
      }
    }
    long h = web.hasArg("h") ? web.arg("h").toInt() : (long)updateIntervalH;
    if (h < (long)UPDATE_MIN_H || h > (long)UPDATE_MAX_H) {   // checked before a press is used up
      web.send(400, "text/plain", "interval must be " + String(UPDATE_MIN_H) + " to " + String(UPDATE_MAX_H) + " hours"); return;
    }
    // A new URL decides what the device blocks from now on, so it needs a press. The
    // interval alone doesn't.
    if (u != updateUrl && !requireConfirm("setupdate", u)) return;
    if (u != updateUrl) audit("update url", u.length() ? u : String("(none)"));
    updateUrl = u;
    updateIntervalH = (uint32_t)h;
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.begin();                             // loopback only; browsers come in through startHttps()
  if (tlsReady && startHttps()) Serial.println("dashboard: https://c3adblock.local");
  else Serial.println("[https] FAILED to start: the dashboard is unreachable");
  httpRedirect.begin();
  if (CONFIRM_LED >= 0) { pinMode(CONFIRM_LED, OUTPUT); ledSet(false); }
  btnStable = btnLast = digitalRead(BOOT_PIN);
  if (otaHashHex.length()) {               // never run network OTA without a password
    ArduinoOTA.setHostname("c3adblock");   // pio run -t upload --upload-port c3adblock.local
    ArduinoOTA.setPasswordHash(otaHashHex.c_str());
    ArduinoOTA.begin();
  }
  Serial.printf("DNS :53 + dashboard https :443%s up\n", otaHashHex.length() ? (physConfirm ? " + OTA (press BOOT to open)" : " + OTA") : "");
}

void loop() {
  loopBeat = millis();
  confirmLoop();
  pollSerial();                           // INFO over USB (start-here.py finds the IP this way)
  // With physical confirmation on, espota only gets an answer for a minute after a BOOT
  // press. An accepted upload runs to completion inside this one handle() call.
  if (otaHashHex.length() && (!physConfirm || otaWindowOpen())) ArduinoOTA.handle();
  web.handleClient();                     // DNS is served by its own task (dnsTask), HTTPS by tlsTask
  handleRedirect();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  delay(2);                               // web/OTA only here; DNS never waits on this
}
