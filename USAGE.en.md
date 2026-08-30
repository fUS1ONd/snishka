# snishka — guide

[English](USAGE.en.md) | [Русский](USAGE.md) · [← README](README.en.md)

## Quick start

```bash
S=skills/snishka/scripts/snihunt.py

# 1. candidate domains from the hoster's subnets (see the abuse disclaimer in the [README](README.en.md))
python3 $S prefixes --asn <hoster-ASN> --near <your-subnet/24> --limit 24 > nets.txt
python3 $S scan --cidr-file nets.txt --conc 150 --bind <uplink-IP> --out alive.txt
python3 $S certs --in alive.txt --conc 60 --out certs.jsonl
python3 $S domains --in certs.jsonl > domains.txt

# 2. test endpoint on your production server (serves 2 MB to any SNI)
python3 $S serve --bind-ip <prod-IP> --port 8000 --size 2097152

# 3. sweep from an uplink behind the DPI — the heart of the method
python3 $S rutest --domains-file domains.txt \
    --dst-ip <prod-IP> --bind <uplink-IP> \
    --mode bulk --bulk-port 8000 --need-bytes 262144 \
    --rounds 3 --conc 4 --delay 0.4 \
    --control-good <known-allowlisted-domain> --control-bad nonexistent.invalid \
    --out verdict.jsonl

# 4. report
python3 $S report --in verdict.jsonl --only-pass
```

## Reading the verdict

We pull `need-bytes` of data from the production IP using the SNI under test:

| Verdict | Meaning |
|---|---|
| `whitelisted` | pulled the full volume — the SNI passes throttling ✅ |
| `throttled` | cut off at ~16–20 KB — the signature of the volume limit |
| `blocked` | 0 bytes / handshake didn't complete |
| `tcp_fail` | TCP didn't open; usually noise from your own load on the target |

The control domains (`--control-good` / `--control-bad`) are printed before the
run. If a known-allowlisted control fails on its own, the measurement is invalid
(wrong channel/phase), not "the SNI is bad". Trust only results stable across all
rounds.

## Selecting a Reality `dest`

An SNI that passes the filter must still work as a masking host: TLS 1.3, X25519
key exchange, ALPN `h2`, returns `200` without redirecting to a foreign domain, a
large and stable site, ideally the same country/hoster as your server. The
`qualify` subcommand checks this.

## Caveats

- The probes' TLS fingerprint is Python's, not a browser's. A DPI that inspects
  the fingerprint (not just SNI/volume) is not reproduced by this method.
- Only the start of the connection and the volume are checked; blocking based on
  long-session behavior won't be seen.
- Allowlists and filtering phases change over time and by region — a list of
  working SNI is short-lived, re-check before relying on it.
- With multiple uplinks always pass `--bind` for the right interface, otherwise
  the measurement takes the default route.
