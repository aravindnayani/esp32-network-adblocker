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
static const int INDEX_ENTRIES = 4096;   // 20 KB first-level flash index
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket (fine up to ~1M hashes; flash holds far fewer)

// ---- globals ----
WebServer web(80);
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

// Bans live only in this list (persisted to /banned.txt), never in the client table: the
// table is a best-effort stats cache that evicts, so a ban stored there could be pushed out
// by a flood of spoofed source addresses, and banned devices that hadn't queried yet since
// boot used to be dropped from the file whenever any other ban changed.
static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

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
// passwords are public, so the real ones are set in the setup portal and kept in NVS.
// A non-placeholder secrets.h still works for source builders. With neither, every
// state-changing endpoint stays locked and network OTA is not started at all.
String adminPass;                   // web dashboard password ("" = none set -> locked)
String otaPass;                     // ArduinoOTA password ("" = OTA disabled)
static const size_t MIN_ADMIN_PASS = 8;

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// BOOT button: held at power-on = recovery; pressed at runtime = approve a pending action.
#if CONFIG_IDF_TARGET_ESP32C3
static const int BOOT_PIN = 9;      // C3 BOOT button
#else
static const int BOOT_PIN = 0;      // classic ESP32 BOOT button (GPIO9 is a flash pin there)
#endif
// LED that blinks while an action waits for the button. -DCONFIRM_LED=-1 to disable.
#ifndef CONFIRM_LED
#if CONFIG_IDF_TARGET_ESP32C3
#define CONFIRM_LED 8               // C3 SuperMini blue LED (active low)
#define CONFIRM_LED_ON LOW
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

static bool isBlocked(const char* domain) {
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
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}
// Ban or unban `ip`. Returns false only if banning and the list is full.
static bool setBanned(uint32_t ip, bool ban) {
  for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) {
    if (!ban) { bannedIP[i] = bannedIP[--numBanned]; saveBanned(); }
    return true;
  }
  if (!ban) return true;
  if (numBanned >= MAX_BAN) return false;
  bannedIP[numBanned++] = ip; saveBanned();
  return true;
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  // Full: reuse the least recently seen entry, so new clients still get counted. Only stats
  // are lost; bans are kept separately (bannedIP).
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
static const uint32_t UPSTREAM_TIMEOUT_MS = 2500;   // then drop it; the client retries
static const int MAX_PENDING = 32;
struct Pending {
  bool used; uint32_t cip; uint16_t cport; uint8_t cid0, cid1;
  uint16_t wid; uint16_t qlen; uint32_t qhash; uint32_t sentAt; uint8_t sock;
};
static Pending pending[MAX_PENDING];
static const int UP_SOCKS = 4;
struct UpSock { int fd; uint8_t inFlight; bool dirty; };   // dirty = used since its port was chosen
static UpSock ups[UP_SOCKS];
static int dnsSock = -1;
static uint8_t dbuf[1536];   // DNS task only; fits any non-fragmented UDP reply (EDNS answers can exceed 512)

static uint32_t fnv32(const uint8_t* p, size_t n) {
  uint32_t h = 2166136261u;
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
// Returns false if the table is full (caller answers SERVFAIL so the client moves on).
static bool forwardUpstream(uint32_t cip, uint16_t cport, int qlen, int qend) {
  int slot = -1;
  for (int i = 0; i < MAX_PENDING; i++) if (!pending[i].used) { slot = i; break; }
  if (slot < 0) return false;
  int k = -1, start = esp_random() % UP_SOCKS;         // random open socket, least loaded
  for (int j = 0; j < UP_SOCKS; j++) {
    int i = (start + j) % UP_SOCKS;
    if (ups[i].fd >= 0 && (k < 0 || ups[i].inFlight < ups[k].inFlight)) k = i;
  }
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
  ups[k].inFlight++; ups[k].dirty = true;
  dbuf[0] = wid >> 8; dbuf[1] = wid & 0xFF;
  sendTo(ups[k].fd, (uint32_t)UPSTREAM, UPSTREAM_PORT, dbuf, qlen);
  return true;
}
static void finishPending(Pending& q) { q.used = false; if (ups[q.sock].inFlight) ups[q.sock].inFlight--; }
static void handleUpstreamReplies(int k) {
  for (int budget = 0; budget < 16; budget++) {
    sockaddr_in from; socklen_t fl = sizeof(from);
    int n = recvfrom(ups[k].fd, dbuf, sizeof(dbuf), MSG_DONTWAIT, (sockaddr*)&from, &fl);
    if (n < 0) break;
    if (from.sin_addr.s_addr != (uint32_t)UPSTREAM || ntohs(from.sin_port) != UPSTREAM_PORT || n < 12) continue;
    uint16_t wid = (dbuf[0] << 8) | dbuf[1];
    for (int i = 0; i < MAX_PENDING; i++) {
      Pending& q = pending[i];
      if (!q.used || q.wid != wid || q.sock != k) continue;
      if (n < 12 + q.qlen || fnv32(dbuf + 12, q.qlen) != q.qhash) break;   // not our question
      dbuf[0] = q.cid0; dbuf[1] = q.cid1;
      sendTo(dnsSock, q.cip, q.cport, dbuf, n);
      finishPending(q);
      break;
    }
  }
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
      blocked = isBannedIP(cip) || (blockingOn && dl && numHashes && isBlocked(domain));
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
    fd_set rf; FD_ZERO(&rf); FD_SET(dnsSock, &rf); int maxfd = dnsSock;
    for (int i = 0; i < UP_SOCKS; i++) if (ups[i].fd >= 0) { FD_SET(ups[i].fd, &rf); if (ups[i].fd > maxfd) maxfd = ups[i].fd; }
    timeval tv = {0, 100000};                         // wake at least every 100 ms to expire
    if (select(maxfd + 1, &rf, nullptr, nullptr, &tv) > 0) {
      for (int i = 0; i < UP_SOCKS; i++) if (ups[i].fd >= 0 && FD_ISSET(ups[i].fd, &rf)) handleUpstreamReplies(i);
      if (FD_ISSET(dnsSock, &rf)) handleClientQueries();
    }
    expirePending();
    rotateUpstreamPorts();
  }
}
static bool startDns() {
  dnsSock = udpSocket(DNS_PORT);
  for (int i = 0; i < UP_SOCKS; i++) { ups[i].fd = -1; ups[i].inFlight = 0; ups[i].dirty = false; }
  rotateUpstreamPorts();
  int open = 0; for (int i = 0; i < UP_SOCKS; i++) open += ups[i].fd >= 0;
  if (dnsSock < 0 || !open) return false;
  // Stack is in bytes; lookups read flash through LittleFS, so leave headroom.
  return xTaskCreate(dnsTask, "dns", 8192, nullptr, 3, nullptr) == pdPASS;
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

// DNS rebinding: a page on evil.example can re-point its own hostname at this device's
// LAN IP. Its fetch() is then "same-origin", so it can set the CSRF header above and
// read /stats.json. The browser still sends Host: evil.example, so only answer requests
// addressed to a name or IP that really is this device.
static bool hostOk() {
  String h = web.hostHeader(); h.toLowerCase();
  int colon = h.indexOf(':'); if (colon >= 0) h = h.substring(0, colon);
  if (h.endsWith(".")) h.remove(h.length() - 1);
  return h == "c3adblock.local" || h == "c3adblock" || h == WiFi.localIP().toString();
}
static bool requireHost() {
  if (hostOk()) return true;
  web.send(403, "text/plain", "bad Host header (use http://c3adblock.local or the device IP)");
  return false;
}
static uint32_t clientIp() { return (uint32_t)web.client().remoteIP(); }

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

// ---------- auth ----------
enum AuthResult { AUTH_OK, AUTH_HOST, AUTH_NOPASS, AUTH_CSRF, AUTH_LOCKED, AUTH_PROMPT, AUTH_CONFIRM };
static AuthResult checkAuth() {
  if (!hostOk()) return AUTH_HOST;
  if (!adminPass.length()) return AUTH_NOPASS;
  if (web.header(CSRF_HEADER) != CSRF_VALUE) return AUTH_CSRF;
  uint32_t ip = clientIp();
  if (lockedFor(ip)) return AUTH_LOCKED;
  if (web.authenticate(WEB_USER, adminPass.c_str())) { clearAuthFails(ip); return AUTH_OK; }
  if (web.hasHeader("Authorization")) recordAuthFail(ip);
  return AUTH_PROMPT;
}
static void sendAuthError(AuthResult r) {
  switch (r) {
    case AUTH_HOST:    web.send(403, "text/plain", "bad Host header (use http://c3adblock.local or the device IP)"); break;
    case AUTH_NOPASS:  web.send(403, "text/plain", "no admin password set: hold BOOT while powering on to run setup"); break;
    case AUTH_CSRF:    web.send(403, "text/plain", "missing CSRF header"); break;
    case AUTH_LOCKED: {
      uint32_t s = lockedFor(clientIp());
      web.sendHeader("Retry-After", String(s));
      web.send(429, "text/plain", "too many wrong passwords from this device: try again in " + String(s) + " s");
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
// While physical confirmation is on, network OTA (espota) also only answers for a minute
// after a BOOT press made with nothing pending. It can be turned off on the dashboard
// (which itself needs a press); BOOT-at-power-on recovery turns it back on.
static const uint32_t CONFIRM_WAIT_MS = 30000, CONFIRM_USE_MS = 60000, OTA_WINDOW_MS = 60000;
// Pauses up to PAUSE_FREE_S need only the password; longer or indefinite ones need a press.
static const uint32_t PAUSE_FREE_S = 1800, PAUSE_MAX_S = 86400;
static const char* const CONFIRM_ACTIONS[] = { "update", "upload", "setupdate", "forgetwifi", "phys", "pause" };
bool physConfirm = true;                         // NVS auth/phys
struct Confirm { char action[12]; uint32_t ip, until; bool approved; };
static Confirm pend = {};                        // action[0] == 0: nothing pending
static uint32_t otaWindowUntil = 0;
static bool confirmActive() { return pend.action[0] && (int32_t)(pend.until - millis()) > 0; }
static bool otaWindowOpen() { return otaWindowUntil && (int32_t)(otaWindowUntil - millis()) > 0; }
static void ledSet(bool on) {
  if (CONFIRM_LED >= 0) digitalWrite(CONFIRM_LED, on ? CONFIRM_LED_ON : !CONFIRM_LED_ON);
}
static void loadPhys() { prefs.begin("auth", true); physConfirm = prefs.getBool("phys", true); prefs.end(); }
static void savePhys() { prefs.begin("auth", false); prefs.putBool("phys", physConfirm); prefs.end(); }
// True if this request may do `action` now; consumes the approval.
static bool consumeConfirm(const char* action) {
  if (!physConfirm) return true;
  if (!confirmActive() || !pend.approved || strcmp(pend.action, action) || pend.ip != clientIp()) return false;
  pend.action[0] = 0;
  return true;
}
static bool requireConfirm(const char* action) {
  if (consumeConfirm(action)) return true;
  audit("unconfirmed", action);
  sendAuthError(AUTH_CONFIRM);
  return false;
}
static void handleConfirm() {
  if (!requireAuth()) return;
  String a = web.arg("a");
  bool known = false;
  for (const char* k : CONFIRM_ACTIONS) if (a == k) known = true;
  if (!known) { web.send(400, "text/plain", "unknown action"); return; }
  if (!physConfirm) { web.send(200, "text/plain", "approved"); return; }
  // Another device can't swap its own action in under someone else's pending one.
  if (confirmActive() && pend.ip != clientIp()) {
    web.send(409, "text/plain", "another device is waiting for a BOOT press; try again in " +
                                String((pend.until - millis()) / 1000 + 1) + " s");
    return;
  }
  copySafe(pend.action, sizeof(pend.action), a.c_str());
  pend.ip = clientIp(); pend.approved = false; pend.until = millis() + CONFIRM_WAIT_MS;
  audit("confirm?", a);
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
    } else if (physConfirm && otaPass.length()) {
      otaWindowUntil = millis() + OTA_WINDOW_MS;
      auditIp(0, "BOOT pressed", "network OTA open for 60 s");
    }
  }
  ledSet(waiting ? (millis() / 150) & 1 : otaWindowOpen() ? (millis() / 600) & 1 : false);
}
static void handleStats() {
  if (!requireHost()) return;
  StateLock lock;
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed + ",\"foreign\":" + totalForeign +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt && (int32_t)(resumeAt - millis()) > 0 ? (resumeAt - millis()) / 1000 : 0) +
             ",\"noauth\":" + (adminPass.length() ? "false" : "true") +
             ",\"phys\":" + (physConfirm ? "true" : "false") + ",\"otaWin\":" + (otaWindowOpen() ? (otaWindowUntil - millis()) / 1000 + 1 : 0);
  if (confirmActive())
    j += ",\"confirm\":{\"a\":\"" + String(pend.action) + "\",\"ip\":\"" + IPAddress(pend.ip).toString() +
         "\",\"state\":\"" + (pend.approved ? "approved" : "pending") + "\",\"left\":" + ((pend.until - millis()) / 1000 + 1) + "}";
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
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (isBannedIP(c.ip)?"true":"false") + "}"; }
  for (int b = 0; b < numBanned; b++) {                  // banned but not in the table (yet): still listed, so it can be unbanned
    bool listed = false;
    for (int i = 0; i < numClients; i++) if (clients[i].ip == bannedIP[b]) { listed = true; break; }
    if (listed) continue;
    j += (numClients || b ? "," : ""); j += "{\"ip\":\"" + IPAddress(bannedIP[b]).toString() + "\",\"mac\":\"00:00:00:00:00:00\",\"blocked\":0,\"allowed\":0,\"banned\":true}";
  }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "]}";
  web.send(200, "application/json", j);
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip;
  if (ip.fromString(web.arg("ip"))) {
    bool banned, ok;
    { StateLock lock; banned = !isBannedIP((uint32_t)ip); ok = setBanned((uint32_t)ip, banned); }
    if (!ok) { web.send(507, "text/plain", "ban list is full (" + String(MAX_BAN) + " devices): unban one first"); return; }
    audit(banned ? "ban" : "unban", ip.toString());
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
// Auth + physical confirmation for an upload, checked when its first part arrives.
static int uploadAuth(const char* action) {
  AuthResult r = checkAuth();
  if (r == AUTH_OK && !consumeConfirm(action)) { audit("unconfirmed", action); r = AUTH_CONFIRM; }
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
      if (upAuth == AUTH_OK && upFile && upWriteOk && upFile.write(u.buf, u.currentSize) != u.currentSize) upWriteOk = false;
      break;
    case UPLOAD_FILE_END: {
      if (upAuth != AUTH_OK) break;
      if (upFile) upFile.close();
      String why = "write failed (flash full?)"; bool ok = false;
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
static void handleFwUpdateDone() {
  int r = fwAuth; fwAuth = AUTH_UNSET;
  if (r == AUTH_UNSET) { if (requireAuth()) web.send(400, "text/plain", "no file received"); return; }
  if (r != AUTH_OK) { sendAuthError((AuthResult)r); return; }
  bool ok = !Update.hasError();
  audit("firmware", ok ? "flashed, rebooting" : "update failed");
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuth = uploadAuth("update");
    if (fwAuth != AUTH_OK) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (fwAuth != AUTH_OK) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (fwAuth != AUTH_OK) return;
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (fwAuth != AUTH_OK) return;
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool isPlaceholder(const char* s, const char* placeholder) { return !s || !*s || strcmp(s, placeholder) == 0; }
// NVS (set in the portal) wins; a real secrets.h value is the fallback for source builds.
static void loadAuth() {
  prefs.begin("auth", true); adminPass = prefs.getString("pass", ""); prefs.end();
  if (!adminPass.length() && !isPlaceholder(WEB_PASS, "CHANGE_ME_WEB_PASSWORD")) adminPass = WEB_PASS;
  otaPass = isPlaceholder(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") ? adminPass : String(OTA_PASS);
}
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

static bool portalNeedsPass() { return adminPass.length() && !portalRecovery; }
static bool sameSecret(const String& a, const String& b) {   // no early exit on the first mismatch
  uint8_t d = a.length() != b.length();
  for (size_t i = 0; i < a.length(); i++) d |= (uint8_t)a[i] ^ (uint8_t)(i < b.length() ? b[i] : 0);
  return d == 0;
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
    (adminPass.length()
      ? String("New dashboard admin password (leave blank to keep the current one):")
      : "Choose a dashboard admin password (8+ characters). It protects firmware updates and settings; user name is <b>" + htmlEscape(WEB_USER) + "</b>.") +
    "</p><input name=a type=password minlength=8 " + String(adminPass.length() ? "" : "required ") +
    "autocomplete=new-password placeholder='Admin password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p"), ap = web.arg("a");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  if (portalNeedsPass()) {
    if (portalFails >= PORTAL_MAX_FAILS) {
      web.send(429, "text/plain", "too many wrong passwords: power-cycle the device, or hold BOOT while powering on to reset it");
      return;
    }
    if (!sameSecret(web.arg("c"), adminPass)) {
      portalFails++;
      Serial.printf("[setup] wrong current admin password (%u/%u)\n", portalFails, PORTAL_MAX_FAILS);
      delay(1000);
      web.send(403, "text/plain", "wrong current admin password");
      return;
    }
  }
  if (ap.length() ? ap.length() < MIN_ADMIN_PASS : !adminPass.length()) {
    web.send(400, "text/plain", "admin password must be at least 8 characters"); return;
  }
  if (ap.length()) { prefs.begin("auth", false); prefs.putString("pass", ap); prefs.end(); }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + htmlEscape(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>c3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
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
  loadCustom(); loadBanned(); loadUpdateCfg();
  Serial.printf("custom: %d, banned: %d\n", numCustom, numBanned);

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

  if (forcePortal || !connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  if (MDNS.begin("c3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c3adblock.local"); }

  if (!adminPass.length())
    Serial.println("[WARN] no admin password set: settings, uploads and OTA are locked. "
                   "Hold BOOT while powering on to run setup and choose one.");

  if (!startDns()) Serial.println("[dns] FAILED to start");
  { const char* hdrs[] = { CSRF_HEADER }; web.collectHeaders(hdrs, 1); }  // needed for requireAuth()'s CSRF check
  web.on("/", []() { if (requireHost()) web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/addblock", []() {
    if (!requireAuth()) return;
    String d = web.arg("d"); const char* why;
    { StateLock lock; why = addCustom(d); }
    if (why) { web.send(400, "text/plain", why); return; }
    audit("block domain", d); web.send(200, "text/plain", "ok");
  });
  web.on("/unblock", []() { if (!requireAuth()) return; String d = web.arg("d"); { StateLock lock; removeCustom(d); } audit("unblock domain", d); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    if (s < 0 || s > (long)PAUSE_MAX_S) { web.send(400, "text/plain", "pause must be 0 (indefinite) to " + String(PAUSE_MAX_S) + " s"); return; }
    // Turning blocking off indefinitely or for long is the quiet way to disable the device,
    // so it needs a BOOT press like the other risky actions. Short pauses stay one click.
    if ((s == 0 || s > (long)PAUSE_FREE_S) && !requireConfirm("pause")) return;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    if (s > 0 && !resumeAt) resumeAt = 1;      // 0 means "indefinite"; don't land on it by wraparound
    audit("pause", s > 0 ? String(s) + " s" : String("indefinitely"));
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; audit("resume"); web.send(200, "text/plain", "resumed"); });
  web.on("/confirm", handleConfirm);         // /confirm?a=<action>: start waiting for a BOOT press
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
    if (u != updateUrl && !requireConfirm("setupdate")) return;
    if (u != updateUrl) audit("update url", u.length() ? u : String("(none)"));
    updateUrl = u;
    updateIntervalH = (uint32_t)h;
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.begin();
  if (CONFIRM_LED >= 0) { pinMode(CONFIRM_LED, OUTPUT); ledSet(false); }
  btnStable = btnLast = digitalRead(BOOT_PIN);
  if (otaPass.length()) {                  // never run network OTA without a password
    ArduinoOTA.setHostname("c3adblock");   // pio run -t upload --upload-port c3adblock.local
    ArduinoOTA.setPassword(otaPass.c_str());
    ArduinoOTA.begin();
  }
  Serial.printf("DNS :53 + dashboard :80%s up\n", otaPass.length() ? (physConfirm ? " + OTA (press BOOT to open)" : " + OTA") : "");
}

void loop() {
  confirmLoop();
  // With physical confirmation on, espota only gets an answer for a minute after a BOOT
  // press. An accepted upload runs to completion inside this one handle() call.
  if (otaPass.length() && (!physConfirm || otaWindowOpen())) ArduinoOTA.handle();
  web.handleClient();                     // DNS is served by its own task (dnsTask)
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  delay(2);                               // web/OTA only here; DNS never waits on this
}
