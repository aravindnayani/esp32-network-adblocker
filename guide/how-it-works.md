# How it works

[← Back to README](../README.md)

## The lookup, step by step

When a device asks "where is `a.b.example.com`?":

1. **Hash the name and its parents.** `a.b.example.com`, `b.example.com` and `example.com` are each turned into a 40-bit FNV-1a hash. That's why blocking a domain also blocks its subdomains.
2. **Check your custom list.** Domains you added on the dashboard are checked first.
3. **Check the cache.** A 256-slot RAM cache answers repeat questions right away.
4. **Check the blocklist.** A 4096-entry index in RAM (20 KB of evenly spaced sample hashes) narrows the search to one small bucket. That bucket comes from flash in a single read and gets scanned.
5. **Answer.** If the name was found, the reply is `0.0.0.0`. If not, the query is forwarded upstream.

## Forwarding allowed queries

- DNS runs in **its own FreeRTOS task**, so dashboard traffic, uploads and blocklist downloads never delay a lookup.
- Each forwarded query gets a fresh random ID and a slot in a **32-entry table**. A reply is only passed back if its ID *and* question match a recorded query.
- Unanswered slots expire after 4 s, and the client retries.
- If all 32 slots are busy, the client gets an immediate SERVFAIL so it can try its backup resolver.

## Encrypted upstream (DNS-over-TLS)

Allowed queries go out inside one TLS connection to `dns.quad9.net:853` (RFC 7858). Your ISP sees a connection to Quad9, not the sites you visit.

- The certificate must chain to a root in `src/ca_bundle.h` **and** name `dns.quad9.net`.
- Queries are pipelined, and answers are matched as they arrive in any order.
- The connection opens when needed and reconnects after Quad9 closes it for being idle. Session resumption keeps reconnects cheap. A full handshake can briefly pause lookups.
- Answers too large for the client's UDP buffer come back truncated with the TC bit set, just like a normal resolver would send them.

**It fails closed.** If port 853 is blocked or the certificate is wrong, lookups get SERVFAIL. They never go out unencrypted. Reconnects back off up to one minute, and the dashboard shows a red banner while the upstream is down.

If your network blocks port 853, build with `-DUPSTREAM_PLAIN` to use plain UDP instead. The dashboard then labels the upstream as unencrypted.

## Why 40-bit hashes?

The number of collisions (two domains sharing a hash) follows the birthday bound:

| Hash size | Collisions at 141k domains | At 250k | At 537k |
|---|---|---|---|
| 32-bit | ~2 | ~7 | ~34 |
| **40-bit (used)** | **~0** | **~0** | **~1** |
| 64-bit | 0 | 0 | 0, but 60% more flash |

A collision means one unlucky domain is blocked by mistake. 40 bits keeps that near zero without wasting flash.

This isn't just a workaround for the C3. On a 16 MB ESP32-S3, the same scheme holds about **2.7 million domains**. Storing the names in 8 MB of PSRAM fits only about 466k.

## How much fits

| Partition layout | Blocklist space | Max domains | Firmware OTA? |
|---|---|---|---|
| Default (`partitions.csv`, two app slots) | ~1.3 MB | ~250k | Yes |
| Single app slot | more | ~537k | No |

The default list is about 140k domains (~0.7 MB).
