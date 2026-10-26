# Third-party notices

pasiv-rx is GPL-3.0-only. It statically links:

- **RandomX** v1.2.1 — https://github.com/tevador/RandomX — BSD-3-Clause,
  vendored in `vendor/RandomX` (licence: `vendor/RandomX/LICENSE`) with three
  Pasiv patches, already applied in the vendored tree and kept as diffs in
  `patches/`:
  - `0001-linux-thp-madvise.patch` — request transparent huge pages for the
    dataset on Linux when hugetlb pages are unavailable;
  - `0002-dead-cfround-elimination.patch` — drop a CFROUND whose rounding
    mode is replaced before any FP instruction reads it (the rule XMRig's
    GPL-3.0 JIT uses; RandomX's own tests and the JIT/interpreter result
    hash agree with it);
  - `0003-linux-scratchpad-thp.patch` — 2 MB-align VM scratchpads on Linux and
    request transparent huge pages for them.
- Rust crates (rustls, ring, webpki-roots, serde_json) under their own
  permissive licences; see `Cargo.lock`.
