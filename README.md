# pasiv-rx

Pasiv's own RandomX CPU miner: tevador/RandomX (vendored) plus a minimal
Monero-style pool client (login / job / submit / keepalived, plain TCP or TLS,
failover across URLs). Built and signed by Pasiv so the Windows CPU lane needs
no Defender exclusion and no UAC prompt.

```
pasiv-rx --url rx.unmineable.com:3333 --url tls://rx.unmineable.com:443 \
         --user COIN:ADDRESS.worker [--threads N]
pasiv-rx --bench [--threads N] [--seconds S]
```

Status: spike. See the Pasiv repo's roadmap (zero-UAC Windows).
