# Third-party notices

pasiv-rx is GPL-3.0-only. It statically links:

- **RandomX** v1.2.1 — https://github.com/tevador/RandomX — BSD-3-Clause,
  vendored in `vendor/RandomX` (licence: `vendor/RandomX/LICENSE`) with one
  Pasiv patch, `patches/0001-linux-thp-madvise.patch` (already applied in the
  vendored tree): request transparent huge pages on Linux when hugetlb pages
  are unavailable.
- Rust crates (rustls, ring, webpki-roots, serde_json) under their own
  permissive licences; see `Cargo.lock`.
