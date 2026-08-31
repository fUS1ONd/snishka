# snishka

[English](README.en.md) | [Русский](README.md)

[![skills.sh](https://skills.sh/b/fUS1ONd/snishka)](https://skills.sh/fUS1ONd/snishka) [![GitHub stars](https://img.shields.io/github/stars/fUS1ONd/snishka?style=flat)](https://github.com/fUS1ONd/snishka/stargazers) [![License: MIT](https://img.shields.io/github/license/fUS1ONd/snishka)](LICENSE) [![Last commit](https://img.shields.io/github/last-commit/fUS1ONd/snishka)](https://github.com/fUS1ONd/snishka/commits)

> A skill that automates the search for an SNI which passes through **volume-based filtering (the 16–20 KB cutoff)**.
Useful for reviving Hetzner, OVH, DigitalOcean and other throttled machines you still have ssh access to.

Works both as a **Claude Code skill** and as a **standalone CLI**
(`python3 snihunt.py …`) — Claude is not required.

---

## 📦 Install

Via `skills` — installs the skill to **any agent** (Claude Code, Cursor, Codex,
Copilot, etc.), autodetecting which ones are present on the machine:

```bash
npx skills@latest add fUS1ONd/snishka
```

Or manually — the tool is self-contained, needs only Python 3 and `cryptography`:

```bash
git clone https://github.com/fUS1ONd/snishka
python3 snishka/skills/snishka/scripts/snihunt.py --help
```

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

## 🩻 The problem

Sometimes the server is alive — ssh, ping and the TLS handshake all reach it, the
IP is **not banned** — yet the VPN won't come up. A common cause: the DPI filters
not by IP but by **SNI combined with volume**. A ClientHello with an
"unrecognized" SNI passes, the handshake even completes, but after ~16–20 KB of
data the connection is strangled (drop/timeout). SNI names on the network's
allowlist flow without limits.

Reality masks traffic behind a `dest`/`serverNames` host. If that name is not on
the allowlist, the VPN dies exactly at the volume limit.
The key fact: **allowlisted hosts live in those same subnets** — large resources
whose names the network lets through.

## ⚙️ How it works

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

## 📖 Next

The full guide — quick start, reading the verdict, selecting an SNI for Reality,
the abuse disclaimer and caveats — is in **[USAGE.en.md](USAGE.en.md)**.
