#!/usr/bin/env python3
"""
snihunt - поиск рабочего SNI (Reality dest) в соседних подсетях хостера.

Конвейер:
  1. prefixes  - вытащить префиксы AS хостера (RIPEstat)
  2. scan      - найти живые хосты с открытым 443
  3. certs     - собрать доменные имена из TLS-сертификатов
  4. qualify   - отсеять непригодные для Reality (TLS1.3 / X25519 / h2 / redirect)
  5. rutest    - проверить с российского аплинка, проходит ли SNI через DPI
  6. report    - свести всё в итоговую таблицу

Запускается без внешних зависимостей кроме `cryptography`.
"""
import argparse
import asyncio
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import subprocess
import time
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# --------------------------------------------------------------------------- utils

def log(*a):
    print(*a, file=sys.stderr, flush=True)


def read_jsonl(path):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


class JsonlWriter:
    """Пишет построчно и сразу флашит - прогон можно прервать без потери данных."""

    def __init__(self, path):
        self.f = open(path, "w")

    def write(self, obj):
        self.f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        self.f.flush()

    def close(self):
        self.f.close()


# --------------------------------------------------------------------------- prefixes

def cmd_prefixes(args):
    """Префиксы автономной системы хостера через RIPEstat."""
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{args.asn}"
    with urllib.request.urlopen(url, timeout=60) as r:
        data = json.load(r)

    mine = ipaddress.ip_network(args.near, strict=False) if args.near else None
    out = []
    for p in data["data"]["prefixes"]:
        try:
            net = ipaddress.ip_network(p["prefix"], strict=False)
        except ValueError:
            continue
        if net.version != 4:
            continue
        if net.prefixlen > args.max_prefixlen:
            continue
        dist = None
        if mine is not None:
            # расстояние по числовому адресу - грубая мера "соседства" подсетей
            dist = abs(int(net.network_address) - int(mine.network_address))
        out.append((dist if dist is not None else 0, str(net)))

    out.sort()
    if args.limit:
        out = out[: args.limit]
    for _, net in out:
        print(net)
    log(f"[prefixes] AS{args.asn}: {len(out)} префиксов")


# --------------------------------------------------------------------------- scan

async def _probe_tcp(ip, port, timeout, sem, bind=None):
    async with sem:
        try:
            local = (bind, 0) if bind else None
            fut = asyncio.open_connection(ip, port, local_addr=local)
            reader, writer = await asyncio.wait_for(fut, timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return ip
        except Exception:
            return None


def _expand_targets(cidrs, exclude, limit, shuffle):
    seen, hosts = set(), []
    ex = [ipaddress.ip_network(e, strict=False) for e in exclude]
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        for ip in net.hosts() if net.prefixlen < 31 else net:
            s = str(ip)
            if s in seen:
                continue
            if any(ip in e for e in ex):
                continue
            seen.add(s)
            hosts.append(s)
    if shuffle:
        random.shuffle(hosts)
    if limit:
        hosts = hosts[:limit]
    return hosts


def _scan_masscan(hosts_cidrs, port, rate, exclude):
    """Быстрый путь для больших диапазонов. Требует root."""
    cmd = ["masscan", "-p", str(port), "--rate", str(rate), "-oL", "-"]
    for e in exclude:
        cmd += ["--exclude", e]
    cmd += hosts_cidrs
    log("[scan] " + " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    found = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "open":
            found.append(parts[3])
    if not found and proc.returncode != 0:
        log("[scan] masscan stderr:", proc.stderr.strip()[:500])
    return found


def _confirm_scan_abuse(cidrs, args):
    """Скан чужих подсетей нарушает ToS хостеров и ловит abuse.

    Особенно опасно запускать это НА VPS самого хостера, чью сеть сканируешь:
    детектор netscan почти гарантированно выпишет abuse и может залочить сервер.
    Поэтому требуем явного подтверждения — флагом или интерактивно.
    """
    msg = (
        "\n⚠️  ВНИМАНИЕ: скан чужих подсетей.\n"
        f"    Целей: {', '.join(cidrs)}\n"
        "    Это активное сканирование сетей, которыми ты не владеешь.\n"
        "    - нарушает ToS большинства хостеров;\n"
        "    - провоцирует abuse-репорт, особенно если запущено НА VPS того же\n"
        "      хостера (Hetzner/OVH детектят netscan к своим диапазонам и грозят\n"
        "      локом сервера);\n"
        "    - ответственность за легальность и последствия — на тебе.\n"
        "    Запускай только против СВОЕЙ сети или там, где у тебя есть явное\n"
        "    разрешение владельца.\n"
    )
    log(msg)
    if getattr(args, "accept_abuse_risk", False):
        log("[scan] --accept-abuse-risk передан, продолжаю.")
        return
    if not sys.stdin.isatty():
        log("[scan] неинтерактивный запуск: подтвердите флагом "
            "--accept-abuse-risk. Прерываю.")
        sys.exit(2)
    try:
        ans = input("    Продолжить? Наберите 'yes' для подтверждения: ").strip()
    except EOFError:
        ans = ""
    if ans.lower() != "yes":
        log("[scan] не подтверждено, прерываю.")
        sys.exit(2)


def cmd_scan(args):
    cidrs = list(args.cidr)
    if args.cidr_file:
        with open(args.cidr_file) as f:
            cidrs += [l.strip() for l in f if l.strip() and not l.startswith("#")]

    _confirm_scan_abuse(cidrs, args)

    if args.masscan:
        alive = _scan_masscan(cidrs, args.port, args.rate, args.exclude)
    else:
        hosts = _expand_targets(cidrs, args.exclude, args.limit, args.shuffle)
        log(f"[scan] целей: {len(hosts)}, порт {args.port}, конкурентность {args.conc}")
        sem = asyncio.Semaphore(args.conc)

        async def run():
            tasks = [
                _probe_tcp(h, args.port, args.timeout, sem, args.bind) for h in hosts
            ]
            res = []
            done = 0
            for fut in asyncio.as_completed(tasks):
                r = await fut
                done += 1
                if r:
                    res.append(r)
                if done % 2000 == 0:
                    log(f"[scan] {done}/{len(hosts)}, живых {len(res)}")
            return res

        alive = asyncio.run(run())

    alive.sort(key=lambda x: ipaddress.ip_address(x))
    with open(args.out, "w") as f:
        f.write("\n".join(alive) + ("\n" if alive else ""))
    log(f"[scan] живых с открытым {args.port}: {len(alive)} -> {args.out}")


# --------------------------------------------------------------------------- certs

def _permissive_ctx(alpn=("h2", "http/1.1")):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if alpn:
        try:
            ctx.set_alpn_protocols(list(alpn))
        except NotImplementedError:
            pass
    return ctx


def _parse_cert(der):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtensionOID, NameOID

    c = x509.load_der_x509_certificate(der)
    names = set()
    try:
        for a in c.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            names.add(str(a.value))
    except Exception:
        pass
    try:
        san = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        names.update(san.value.get_values_for_type(x509.DNSName))
    except Exception:
        pass
    issuer = ""
    try:
        issuer = next(
            iter(c.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)), None
        )
        issuer = str(issuer.value) if issuer else ""
    except Exception:
        pass
    return {
        "names": sorted(n.lower().lstrip("*.") for n in names if n),
        "issuer": issuer,
        "not_after": c.not_valid_after_utc.isoformat()
        if hasattr(c, "not_valid_after_utc")
        else str(c.not_valid_after),
        "fp_sha256": c.fingerprint(hashes.SHA256()).hex(),
    }


def _grab_cert(ip, port, timeout, sni=None):
    """TLS-хендшейк ради сертификата. Без SNI отдаётся дефолтный vhost."""
    ctx = _permissive_ctx()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=sni) as s:
                der = s.getpeercert(binary_form=True)
                info = _parse_cert(der) if der else {"names": []}
                info.update(
                    {
                        "ip": ip,
                        "port": port,
                        "tls": s.version(),
                        "alpn": s.selected_alpn_protocol(),
                        "cipher": s.cipher()[0] if s.cipher() else None,
                    }
                )
                return info
    except Exception as e:
        return {"ip": ip, "port": port, "error": f"{type(e).__name__}: {e}"[:200]}


def cmd_certs(args):
    ips = [l.strip() for l in open(args.inp) if l.strip()]
    log(f"[certs] хостов: {len(ips)}")
    out = JsonlWriter(args.out)
    ok = 0
    with ThreadPoolExecutor(max_workers=args.conc) as pool:
        for i, res in enumerate(
            pool.map(lambda ip: _grab_cert(ip, args.port, args.timeout), ips), 1
        ):
            if res.get("names"):
                ok += 1
                out.write(res)
            if i % 200 == 0:
                log(f"[certs] {i}/{len(ips)}, с сертификатом {ok}")
    out.close()
    log(f"[certs] сертификатов собрано: {ok} -> {args.out}")


# --------------------------------------------------------------------------- qualify

# Reality проксирует хендшейк на dest, поэтому dest должен вести себя как
# обычный крупный сайт: TLS1.3, X25519, h2, отсутствие редиректа на другой домен.
BAD_NAME_RE = re.compile(
    r"(^|\.)(localhost|local|internal|lan|home|test|invalid|example)\.?$"
    r"|^\*$|^\d+\.\d+\.\d+\.\d+$|ingress|traefik|kubernetes|plesk|cpanel|synology"
    r"|router|nas\.|vpn\.|proxy\.|mail\.|smtp\.|imap\.|webmail",
    re.I,
)
SELF_SIGNED_ISSUERS = re.compile(r"(internet widgits|acme|snakeoil|kubernetes|default)", re.I)


def _openssl_probe(domain, ip, port, timeout, group="X25519"):
    """Один хендшейк через openssl - оттуда видно и группу, и ALPN."""
    cmd = [
        "openssl", "s_client",
        "-connect", f"{ip}:{port}",
        "-servername", domain,
        "-tls1_3",
        "-groups", group,
        "-alpn", "h2,http/1.1",
        "-verify_return_error",
        "-brief",
    ]
    try:
        p = subprocess.run(
            cmd, input="", capture_output=True, text=True,
            errors="replace", timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "reason": "timeout"}
    txt = p.stdout + p.stderr
    established = "CONNECTION ESTABLISHED" in txt
    tls13 = "Protocol version: TLSv1.3" in txt
    # -brief печатает согласованную группу как "Server Temp Key: ECDH, X25519, 253 bits";
    # раз мы предложили только запрошенную группу, успешный хендшейк её и подтверждает
    grp = re.search(r"Server Temp Key:\s*ECDH,\s*([^,]+),", txt)
    return {
        "ok": established and tls13,
        "tls13": tls13,
        "group": grp.group(1).strip() if grp else (group if established else None),
        "verify_ok": "Verification: OK" in txt,
        "raw": "" if established else txt[-300:],
    }


def _http_probe(domain, ip, port, timeout):
    """HEAD через curl с --resolve: проверяем h2, статус и куда редиректит."""
    cmd = [
        "curl", "-sS", "-o", "/dev/null", "--http2",
        "--resolve", f"{domain}:{port}:{ip}",
        "--max-time", str(timeout),
        "-w", "%{http_code} %{http_version} %{redirect_url}",
        f"https://{domain}/",
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=timeout + 3)
    except subprocess.TimeoutExpired:
        return {"code": None, "http_version": None, "redirect": None}
    parts = (p.stdout or "").split()
    return {
        "code": parts[0] if len(parts) > 0 else None,
        "http_version": parts[1] if len(parts) > 1 else None,
        "redirect": parts[2] if len(parts) > 2 else "",
    }


# Близость домена к хосту, откуда взят сертификат. Хороший Reality dest — это
# домен, чей реальный TLS живёт на том же IP (или хотя бы в той же сети хостера),
# а не «уведённое» имя, резолвящееся в чужой CDN/зеркало.
PROX_SAME_IP = "same-ip"      # домен резолвится ровно в IP этого хоста
PROX_SAME_24 = "same-24"      # в тот же /24
PROX_SAME_ASN = "same-asn"    # в один из префиксов хостера
PROX_OFFNET = "offnet"        # в чужой IP — вероятно CDN/зеркало/прокси
PROX_NODNS = "no-dns"         # не резолвится

# ранжирование близости: чем меньше индекс, тем лучше кандидат
PROX_RANK = {
    PROX_SAME_IP: 0, PROX_SAME_24: 1, PROX_SAME_ASN: 2,
    PROX_OFFNET: 3, PROX_NODNS: 4,
}


def _resolve_ips(domain, timeout):
    """A-записи домена. Пустой список, если не резолвится."""
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
        return sorted({i[4][0] for i in infos})
    except (socket.gaierror, socket.timeout, OSError):
        return []
    finally:
        socket.setdefaulttimeout(old)


def _classify_proximity(domain, host_ip, prefixes, timeout):
    """Сравнить, во что резолвится домен, с IP хоста и сетью хостера.

    prefixes — список ipaddress-сетей хостера (из команды prefixes), может быть
    пустым: тогда классификация ограничивается same-ip / same-24 / offnet.
    """
    resolved = _resolve_ips(domain, timeout)
    if not resolved:
        return PROX_NODNS, []
    ips = [ipaddress.ip_address(r) for r in resolved]
    if host_ip in resolved:
        return PROX_SAME_IP, resolved
    try:
        host_net = ipaddress.ip_network(host_ip + "/24", strict=False)
        if any(a in host_net for a in ips):
            return PROX_SAME_24, resolved
    except ValueError:
        pass
    if prefixes and any(any(a in net for net in prefixes) for a in ips):
        return PROX_SAME_ASN, resolved
    return PROX_OFFNET, resolved


def _qualify_one(rec, args):
    ip = rec["ip"]
    for domain in rec["names"][: args.names_per_host]:
        if BAD_NAME_RE.search(domain) or "." not in domain:
            continue
        if SELF_SIGNED_ISSUERS.search(rec.get("issuer", "")):
            continue
        tls = _openssl_probe(domain, ip, args.port, args.timeout,
                             group="X25519" if args.require_x25519 else "X25519:P-256:P-384")
        if not tls.get("ok"):
            continue
        if args.require_valid_cert and not tls.get("verify_ok"):
            continue
        http = _http_probe(domain, ip, args.port, args.timeout)
        redirect = http.get("redirect") or ""
        redirects_away = bool(redirect) and domain not in redirect
        proximity, resolved = _classify_proximity(
            domain, ip, args.prefixes, args.timeout
        )
        yield {
            "domain": domain,
            "ip": ip,
            "issuer": rec.get("issuer"),
            "tls13": tls.get("tls13"),
            "group": tls.get("group"),
            "verify_ok": tls.get("verify_ok"),
            "http_code": http.get("code"),
            "http_version": http.get("http_version"),
            "redirect": redirect,
            "redirects_away": redirects_away,
            "h2": http.get("http_version") == "2",
            "proximity": proximity,
            "resolved": resolved,
        }


def _load_prefixes(path):
    """CIDR-префиксы хостера из файла (вывод команды prefixes)."""
    if not path:
        return []
    nets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                pass
    return nets


def cmd_qualify(args):
    recs = list(read_jsonl(args.inp))
    args.prefixes = _load_prefixes(args.prefixes_file)
    log(f"[qualify] хостов на проверку: {len(recs)}"
        + (f", префиксов хостера: {len(args.prefixes)}" if args.prefixes else
           " (без префиксов — same-asn не различается)"))
    if args.max_proximity not in PROX_RANK:
        args.max_proximity = PROX_OFFNET
    out = JsonlWriter(args.out)
    n = 0
    from collections import Counter
    prox_stats = Counter()

    def work(rec):
        # сбой на одном хосте не должен ронять весь прогон
        try:
            return list(_qualify_one(rec, args))
        except Exception as e:
            log(f"[qualify] {rec.get('ip')}: {type(e).__name__}: {e}")
            return []

    with ThreadPoolExecutor(max_workers=args.conc) as pool:
        for i, batch in enumerate(pool.map(work, recs), 1):
            for c in batch:
                if args.require_h2 and not c["h2"]:
                    continue
                if args.no_redirect and c["redirects_away"]:
                    continue
                # отсев по близости: offnet-домены (CDN/зеркала/чужой IP) —
                # плохие dest, если пользователь не разрешил их явно
                if PROX_RANK[c["proximity"]] > PROX_RANK[args.max_proximity]:
                    continue
                prox_stats[c["proximity"]] += 1
                out.write(c)
                n += 1
            if i % 100 == 0:
                log(f"[qualify] {i}/{len(recs)}, кандидатов {n}")
    out.close()
    stats = ", ".join(f"{k}={v}" for k, v in sorted(
        prox_stats.items(), key=lambda kv: PROX_RANK[kv[0]]))
    log(f"[qualify] кандидатов: {n} -> {args.out}" + (f" ({stats})" if stats else ""))


# --------------------------------------------------------------------------- rutest

# Классификация исхода ClientHello, отправленного из РФ.
#   pass   - до сервера дошло (получили TLS-ответ или alert) => SNI не режется
#   reset  - RST после ClientHello => характерный след DPI
#   timeout- молчание => дроп пакета
VERDICT_PASS = "pass"
VERDICT_RESET = "reset"
VERDICT_TIMEOUT = "timeout"
VERDICT_TCPFAIL = "tcp_fail"

# Вердикты объёмного режима: провайдер держит белый список SNI, всё остальное
# душится после нескольких десятков килобайт.
VERDICT_WHITE = "whitelisted"
VERDICT_THROTTLED = "throttled"
VERDICT_BLOCKED = "blocked"


def _bulk_probe(domain, dst_ip, port, path, timeout, bind, need_bytes):
    """Качаем через TLS с нужным SNI и считаем байты до обрыва."""
    ctx = _permissive_ctx()
    raw = socket.socket()
    raw.settimeout(timeout)
    n = 0
    try:
        if bind:
            raw.bind((bind, 0))
        raw.connect((dst_ip, port))
    except OSError as e:
        raw.close()
        return VERDICT_TCPFAIL, 0, str(e)[:80]
    try:
        w = ctx.wrap_socket(raw, server_hostname=domain)
    except ssl.SSLError as e:
        raw.close()
        return VERDICT_BLOCKED, 0, f"tls: {e.reason or e}"[:80]
    except (ConnectionResetError, socket.timeout, OSError) as e:
        raw.close()
        return VERDICT_BLOCKED, 0, f"handshake: {type(e).__name__}"
    try:
        req = (
            f"GET {path} HTTP/1.1\r\nHost: {domain}\r\n"
            "Accept-Encoding: identity\r\n"
            "User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        )
        w.sendall(req.encode())
        while n < need_bytes:
            b = w.recv(32768)
            if not b:
                break
            n += len(b)
        end = "eof" if n < need_bytes else "enough"
    except (ConnectionResetError, socket.timeout, ssl.SSLError, OSError) as e:
        end = type(e).__name__
    finally:
        try:
            w.close()
        except Exception:
            pass
    if n >= need_bytes:
        return VERDICT_WHITE, n, end
    if n == 0:
        return VERDICT_BLOCKED, n, end
    return VERDICT_THROTTLED, n, end


def _ru_probe(domain, dst_ip, port, timeout, bind):
    """Шлём ClientHello с нужным SNI на боевой IP и смотрим, дошёл ли он."""
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        if bind:
            raw.bind((bind, 0))
        raw.connect((dst_ip, port))
    except socket.timeout:
        raw.close()
        return VERDICT_TCPFAIL, "connect timeout"
    except OSError as e:
        raw.close()
        return VERDICT_TCPFAIL, str(e)

    ctx = _permissive_ctx()
    try:
        s = ctx.wrap_socket(raw, server_hostname=domain)
        s.close()
        return VERDICT_PASS, "full handshake"
    except ssl.SSLError as e:
        # alert / протокольная ошибка означает, что сервер нас услышал
        return VERDICT_PASS, f"tls: {e.reason or e}"
    except ConnectionResetError:
        return VERDICT_RESET, "RST after ClientHello"
    except socket.timeout:
        return VERDICT_TIMEOUT, "no reply to ClientHello"
    except OSError as e:
        return VERDICT_RESET, str(e)
    finally:
        try:
            raw.close()
        except Exception:
            pass


def _ru_check(domain, args):
    from collections import Counter

    verdicts, sizes = [], []
    for i in range(args.rounds):
        if i and args.delay:
            time.sleep(args.delay)
        if args.mode == "bulk":
            v, n, detail = _bulk_probe(
                domain, args.dst_ip, args.bulk_port, args.bulk_path,
                args.timeout, args.bind, args.need_bytes,
            )
            sizes.append(n)
        else:
            v, detail = _ru_probe(
                domain, args.dst_ip, args.port, args.timeout, args.bind
            )
        verdicts.append((v, detail))
    counts = Counter(v for v, _ in verdicts)
    good = VERDICT_WHITE if args.mode == "bulk" else VERDICT_PASS
    passes = counts[good]
    # tcp_fail - это шум от собственной нагрузки на цель, а не приговор SNI:
    # он не должен перебивать успешные раунды
    ranked = [v for v in counts if v != VERDICT_TCPFAIL] or list(counts)
    verdict = max(ranked, key=lambda v: (counts[v], v == good))
    return {
        "domain": domain,
        "mode": args.mode,
        "rounds": args.rounds,
        "passes": passes,
        "counts": dict(counts),
        "verdict": verdict,
        "stable": passes == args.rounds,
        "bytes": sizes,
        "min_bytes": min(sizes) if sizes else None,
        "details": [d for _, d in verdicts][:2],
    }


def cmd_rutest(args):
    if args.domains or args.domains_file:
        domains = list(args.domains or [])
        if args.domains_file:
            with open(args.domains_file) as f:
                domains += [
                    l.strip() for l in f if l.strip() and not l.startswith("#")
                ]
    else:
        domains = []
        seen = set()
        for r in read_jsonl(args.inp):
            d = r["domain"]
            if d not in seen:
                seen.add(d)
                domains.append(d)

    # контроли: заведомо живой SNI и заведомо мусорный
    controls = [args.control_good, args.control_bad]
    port = args.bulk_port if args.mode == "bulk" else args.port
    log(f"[rutest] режим {args.mode}, цель {args.dst_ip}:{port}, "
        f"bind={args.bind or 'auto'}"
        + (f", порог {args.need_bytes // 1024} KiB" if args.mode == "bulk" else ""))
    for c in controls:
        r = _ru_check(c, args)
        size = f", {r['min_bytes']} B" if r.get("min_bytes") is not None else ""
        log(f"[rutest] контроль {c}: {r['verdict']} "
            f"({r['passes']}/{r['rounds']}{size})")

    log(f"[rutest] доменов: {len(domains)}, раундов на домен: {args.rounds}")
    out = JsonlWriter(args.out)
    good = 0
    with ThreadPoolExecutor(max_workers=args.conc) as pool:
        for i, r in enumerate(pool.map(lambda d: _ru_check(d, args), domains), 1):
            out.write(r)
            if r["stable"]:
                good += 1
                log(f"[rutest] + {r['domain']} ({r['verdict']})")
            if i % 50 == 0:
                log(f"[rutest] {i}/{len(domains)}, найдено {good}")
    out.close()
    log(f"[rutest] стабильно проходят: {good} -> {args.out}")


# --------------------------------------------------------------------------- domains

# Белый список у провайдера - это российские ресурсы, поэтому доменные зоны
# РФ проверяем первыми: на них шанс попадания несопоставимо выше.
RU_ZONES = (".ru", ".su", ".рф", ".xn--p1ai", ".moscow", ".tatar")


def _etld1(domain):
    """Грубый eTLD+1: белый список ведётся по домену организации, не по хосту."""
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    # двухуровневые зоны вида co.uk, com.ru, net.ru
    if len(parts[-2]) <= 3 and parts[-2] in ("co", "com", "net", "org", "gov", "ac"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def cmd_domains(args):
    seen, ru, other = set(), [], []
    for rec in read_jsonl(args.inp):
        for name in rec.get("names", []):
            if BAD_NAME_RE.search(name) or "." not in name:
                continue
            key = _etld1(name) if args.etld1 else name
            if key in seen:
                continue
            seen.add(key)
            (ru if key.endswith(RU_ZONES) else other).append(key)
    ru.sort()
    other.sort()
    out = ru + ([] if args.ru_only else other)
    if args.limit:
        out = out[: args.limit]
    print("\n".join(out))
    log(f"[domains] уникальных: {len(seen)} (RU-зоны {len(ru)}), выдано {len(out)}")


# --------------------------------------------------------------------------- serve

def cmd_serve(args):
    """Тестовый TLS-эндпоинт: принимает любой SNI, отдаёт заданный объём.

    Нужен, чтобы мерить лимит объёма для произвольного SNI - боевые сервисы
    отвечают только на свои имена.
    """
    import threading
    import tempfile

    cert, key = args.cert, args.key
    if not (cert and key):
        d = tempfile.mkdtemp(prefix="snihunt-")
        cert, key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
             "-out", cert, "-days", "5", "-nodes", "-subj", "/CN=snihunt.test"],
            check=True, capture_output=True,
        )
        log(f"[serve] самоподписанный сертификат: {cert}")

    payload = b"A" * args.size
    head = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(payload)
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind_ip, args.port))
    srv.listen(64)
    log(f"[serve] {args.bind_ip}:{args.port}, отдаёт {args.size // 1024} KiB "
        f"на любой SNI. Ctrl-C для остановки.")

    def handle(conn):
        try:
            conn.settimeout(20)
            s = ctx.wrap_socket(conn, server_side=True)
            s.recv(4096)
            s.sendall(head + payload)
            s.close()
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
    except KeyboardInterrupt:
        log("[serve] остановлен")
    finally:
        srv.close()


# --------------------------------------------------------------------------- report

def cmd_report(args):
    cand = {}
    if args.qualified and os.path.exists(args.qualified):
        for r in read_jsonl(args.qualified):
            cand.setdefault(r["domain"], r)

    rows = []
    for r in read_jsonl(args.inp):
        q = cand.get(r["domain"], {})
        rows.append(
            {
                "domain": r["domain"],
                "verdict": r["verdict"],
                "passes": f"{r['passes']}/{r['rounds']}",
                "_passes": r["passes"],
                "min_kib": (f"{r['min_bytes'] / 1024:.0f}"
                            if r.get("min_bytes") is not None else "-"),
                "ip": q.get("ip", "-"),
                "prox": q.get("proximity", "-"),
                "_prox_rank": PROX_RANK.get(q.get("proximity"), 9),
                "h2": "да" if q.get("h2") else "нет",
                "group": q.get("group", "-"),
                "code": q.get("http_code", "-"),
                "redirect": "уводит" if q.get("redirects_away") else "нет",
            }
        )
    good = {VERDICT_PASS, VERDICT_WHITE}
    # сортировка: сперва прошедшие DPI, затем самые близкие к хостеру
    # (same-ip раньше same-asn), потом по стабильности и h2
    rows.sort(key=lambda x: (x["verdict"] not in good, x["_prox_rank"],
                             -x["_passes"], x["h2"] != "да", x["domain"]))
    if args.only_pass:
        rows = [r for r in rows if r["verdict"] in good]

    if not rows:
        print("Нет данных.")
        return
    for r in rows:
        r.pop("_passes", None)
        r.pop("_prox_rank", None)
    keys = list(rows[0])
    w = [max(len(str(r[k])) for r in rows + [{k: k}]) for k in keys]
    print("  ".join(k.ljust(w[i]) for i, k in enumerate(keys)))
    print("  ".join("-" * w[i] for i in range(len(keys))))
    for r in rows:
        print("  ".join(str(r[k]).ljust(w[i]) for i, k in enumerate(keys)))
    ok = sum(1 for r in rows if r["verdict"] in good)
    print(f"\nВсего: {len(rows)}, годных SNI: {ok}")


# --------------------------------------------------------------------------- cli

def main():
    p = argparse.ArgumentParser(prog="snihunt", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("prefixes", help="префиксы AS хостера")
    sp.add_argument("--asn", type=int, default=24940)
    sp.add_argument("--near", help="свой префикс, для сортировки по соседству")
    sp.add_argument("--max-prefixlen", type=int, default=20)
    sp.add_argument("--limit", type=int, default=0)
    sp.set_defaults(func=cmd_prefixes)

    sp = sub.add_parser("scan", help="скан 443 по подсетям")
    sp.add_argument("--cidr", action="append", default=[])
    sp.add_argument("--cidr-file")
    sp.add_argument("--port", type=int, default=443)
    sp.add_argument("--conc", type=int, default=800)
    sp.add_argument("--timeout", type=float, default=3.0)
    sp.add_argument("--limit", type=int, default=0)
    sp.add_argument("--shuffle", action="store_true")
    sp.add_argument("--exclude", action="append", default=[])
    sp.add_argument("--bind", help="локальный IP (выбор аплинка)")
    sp.add_argument("--masscan", action="store_true", help="быстрый путь, нужен root")
    sp.add_argument("--rate", type=int, default=2000)
    sp.add_argument("--accept-abuse-risk", action="store_true",
                    help="подтвердить, что понимаешь риск abuse при скане чужих "
                         "сетей (обязателен при неинтерактивном запуске)")
    sp.add_argument("--out", default="alive.txt")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("certs", help="собрать домены из сертификатов")
    sp.add_argument("--in", dest="inp", default="alive.txt")
    sp.add_argument("--port", type=int, default=443)
    sp.add_argument("--conc", type=int, default=100)
    sp.add_argument("--timeout", type=float, default=6.0)
    sp.add_argument("--out", default="certs.jsonl")
    sp.set_defaults(func=cmd_certs)

    sp = sub.add_parser("qualify", help="отсев по пригодности для Reality")
    sp.add_argument("--in", dest="inp", default="certs.jsonl")
    sp.add_argument("--port", type=int, default=443)
    sp.add_argument("--conc", type=int, default=24)
    sp.add_argument("--timeout", type=float, default=8.0)
    sp.add_argument("--names-per-host", type=int, default=3)
    sp.add_argument("--require-x25519", action="store_true", default=True)
    sp.add_argument("--no-require-x25519", dest="require_x25519", action="store_false")
    sp.add_argument("--require-valid-cert", action="store_true", default=True)
    sp.add_argument("--no-require-valid-cert", dest="require_valid_cert",
                    action="store_false")
    sp.add_argument("--require-h2", action="store_true", default=True)
    sp.add_argument("--no-require-h2", dest="require_h2", action="store_false")
    sp.add_argument("--no-redirect", action="store_true", default=True)
    sp.add_argument("--allow-redirect", dest="no_redirect", action="store_false")
    sp.add_argument("--prefixes-file",
                    help="файл с CIDR хостера (вывод команды prefixes) — нужен, "
                         "чтобы различать same-asn от offnet")
    sp.add_argument("--max-proximity", default=PROX_SAME_ASN,
                    choices=[PROX_SAME_IP, PROX_SAME_24, PROX_SAME_ASN, PROX_OFFNET],
                    help="худшая допустимая близость домена к хосту: по умолчанию "
                         "same-asn (домен должен резолвиться в сеть хостера); "
                         "offnet — разрешить и чужие IP (CDN/зеркала)")
    sp.add_argument("--out", default="candidates.jsonl")
    sp.set_defaults(func=cmd_qualify)

    sp = sub.add_parser("rutest", help="проверка прохождения SNI через DPI (запускать из РФ)")
    sp.add_argument("--in", dest="inp", default="candidates.jsonl")
    sp.add_argument("--domains", nargs="*", help="проверить конкретные домены")
    sp.add_argument("--domains-file", help="файл со списком доменов, по одному в строке")
    sp.add_argument("--mode", choices=["bulk", "handshake"], default="bulk",
                    help="bulk: качать данные и ловить лимит объёма (основной); "
                         "handshake: только ClientHello")
    sp.add_argument("--bulk-port", type=int, default=8000,
                    help="порт тестового эндпоинта (см. команду serve)")
    sp.add_argument("--bulk-path", default="/")
    sp.add_argument("--need-bytes", type=int, default=512 * 1024,
                    help="сколько байт надо прокачать, чтобы счесть SNI белым")
    sp.add_argument("--dst-ip", required=True, help="боевой IP сервера с Reality")
    sp.add_argument("--port", type=int, default=443)
    sp.add_argument("--bind", help="локальный IP нужного аплинка (wifi/модем)")
    sp.add_argument("--rounds", type=int, default=3)
    sp.add_argument("--conc", type=int, default=3,
                    help="держать низкой: все пробы бьют в один IP")
    sp.add_argument("--delay", type=float, default=0.4,
                    help="пауза между раундами одного домена, сек")
    sp.add_argument("--timeout", type=float, default=6.0)
    sp.add_argument("--control-good", default="2ip.ru")
    sp.add_argument("--control-bad", default="www.pornhub.com")
    sp.add_argument("--out", default="verdict.jsonl")
    sp.set_defaults(func=cmd_rutest)

    sp = sub.add_parser("domains", help="уникальные домены из certs.jsonl")
    sp.add_argument("--in", dest="inp", default="certs.jsonl")
    sp.add_argument("--etld1", action="store_true", default=True,
                    help="схлопывать до домена организации")
    sp.add_argument("--no-etld1", dest="etld1", action="store_false")
    sp.add_argument("--ru-only", action="store_true",
                    help="только российские зоны")
    sp.add_argument("--limit", type=int, default=0)
    sp.set_defaults(func=cmd_domains)

    sp = sub.add_parser("serve", help="временный TLS-эндпоинт для замера объёма")
    sp.add_argument("--bind-ip", default="0.0.0.0")
    sp.add_argument("--port", type=int, default=8000)
    sp.add_argument("--size", type=int, default=2 * 1024 * 1024)
    sp.add_argument("--cert")
    sp.add_argument("--key")
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser("report", help="итоговая таблица")
    sp.add_argument("--in", dest="inp", default="verdict.jsonl")
    sp.add_argument("--qualified", default="candidates.jsonl")
    sp.add_argument("--only-pass", action="store_true")
    sp.set_defaults(func=cmd_report)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
