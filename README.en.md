# snishka

**Read in another language:** [Русский](README.md)

Find an SNI that survives **SNI-based volumetric throttling** — on your own
hosting, so that VLESS + Reality (Xray) works again where the network chokes
unrecognized TLS.

Works both as a **Claude Code skill** and as a **standalone CLI**
(`python3 snihunt.py …`) — Claude is not required.

---

## The problem

Sometimes the server is alive — ssh, ping and the TLS handshake all reach it, the
IP is **not banned** — yet the VPN won't come up. A common cause: the DPI filters
not by IP but by **SNI combined with volume**. A ClientHello with an
"unrecognized" SNI passes, the handshake even completes, but after ~16–20 KB of
data the connection is strangled (drop/timeout). SNI names on the network's
allowlist flow without limits.

Reality masks traffic behind a `dest`/`serverNames` host. If that name is not on
the allowlist, the VPN dies exactly at the volume limit. Whole data centers of
popular hosting providers fall under this: their subnets aren't blocked wholesale
(too much legitimate traffic there), but all unrecognized TLS to them is
throttled.

The key fact: **allowlisted hosts live in those same subnets** — large resources
whose names the network lets through. Set such a name as your Reality `dest` and
your VPN hides behind an "approved" SNI in the same network — and a server that
looked dead works again.

## How it works

The core principle: measure **not "does the SNI owner's website load"**, but how
much data you can pull **to your own server's production IP** using that SNI. The
former measures a path to someone else's address and lies. The latter is exactly
the path your VPN will take.

Hence the pipeline:

1. **discovery** — collect candidate domains from the hoster's neighboring subnets
   (via certificates) or from Certificate Transparency;
2. **serve** — bring up a TLS endpoint on your production server that returns a
   large response to **any** SNI;
3. **rutest** — from an uplink behind the DPI, download that endpoint while
   swapping the SNI, and catch which ones break the volume threshold
   (allowlisted) vs. get strangled at ~16 KB;
4. **qualify** — keep the ones that pass and are also usable as a Reality `dest`
   (TLS 1.3 + X25519 + h2, returning `200` without redirect).

## Install

As a Claude Code skill (copies into `~/.claude/skills/snishka`):

```bash
npx github:fUS1ONd/snishka
```

Or manually — the tool is self-contained, needs only Python 3 and `cryptography`:

```bash
git clone https://github.com/fUS1ONd/snishka
python3 snishka/skill/scripts/snihunt.py --help
```

## Quick start

```bash
S=skill/scripts/snihunt.py

# 1. candidate domains from the hoster's subnets (see the abuse disclaimer below!)
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

## ⚠️ On abuse and legality

The discovery stage can actively scan port 443 across the hoster's subnets. **This
is scanning networks you don't own:**

- it violates the ToS of most hosting providers;
- it triggers abuse reports. Large hosters (Hetzner, OVH, etc.) detect netscans to
  their ranges and may **lock your server**;
- **it is especially dangerous to run the scan on a VPS of the same hoster whose
  network you're scanning** — the shortest path to an abuse report and a lock.

Therefore the `scan` command requires an explicit acknowledgment of the risk
(interactively or via `--accept-abuse-risk`). A lower-risk alternative for
discovery is to take domains from **Certificate Transparency** (crt.sh) without
sending a single packet into someone else's network.

Responsibility for the legality and consequences of use rests with the user. Run
active probes only against **your own** infrastructure or where you have the
owner's explicit permission.

## Caveats

- The probes' TLS fingerprint is Python's, not a browser's. A DPI that inspects
  the fingerprint (not just SNI/volume) is not reproduced by this method.
- Only the start of the connection and the volume are checked; blocking based on
  long-session behavior won't be seen.
- Allowlists and filtering phases change over time and by region — a list of
  working SNI is short-lived, re-check before relying on it.
- With multiple uplinks always pass `--bind` for the right interface, otherwise
  the measurement takes the default route.

## License

[MIT](LICENSE)
