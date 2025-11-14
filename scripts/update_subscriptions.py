#!/usr/bin/env python3
"""Aggregate remote Clash subscription links into a curated configuration.

The script fetches a list of subscription URLs, normalises and merges their
proxy definitions, performs basic TCP latency measurements, and writes a Clash
configuration optimised for popular services. Nodes whose average TCP
connection latency exceeds the configured threshold are excluded from the
resulting configuration.

The script is designed to be executed locally or inside GitHub Actions.  It is
stateless: every run regenerates the output configuration from scratch.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import dataclasses
import hashlib
import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import parse_qs, unquote, urlparse

import yaml
import requests

DEFAULT_TIMEOUT = 15
LATENCY_THRESHOLD_MS = 500.0
DEFAULT_TEST_TIMEOUT = 5.0
SUBSCRIPTION_URLS: Sequence[str] = (
    "https://snip.soulbar.ggff.net/sub/204774c0-99c5-4454-bbd8-86775343a538",
    "https://boy.solobar.dpdns.org/soul/sub",
    "https://bfree.pages.dev/sub/normal/f5c17701-c7d6-4fe4-b8b9-70fdd5e20ace?app=clash#%F0%9F%92%A6%20BPB%20Normal",
    "https://solo-production-0eb5.up.railway.app/solo",
    "http://103.99.52.140:2096/sub/india",
)
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (AggregatorBot; +https://github.com/)"
}

SUPPORTED_TYPES = {"vmess", "vless", "trojan", "ss"}


@dataclasses.dataclass
class Proxy:
    name: str
    type: str
    server: str
    port: int
    data: Dict[str, Any]
    latency_ms: Optional[float] = None

    def to_clash_dict(self) -> Dict[str, Any]:
        base = {"name": self.name, "type": self.type, "server": self.server, "port": self.port}
        base.update(self.data)
        return base


def log_setup(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )


def fetch_content(url: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    logging.info("Fetching subscription: %s", url)
    response = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout)
    response.raise_for_status()
    content_bytes = response.content
    decoded = try_decode_base64(content_bytes)
    if decoded is not None:
        logging.debug("Decoded base64 content from %s", url)
        return decoded
    return content_bytes.decode("utf-8", errors="ignore")


def try_decode_base64(content: bytes) -> Optional[str]:
    stripped = re.sub(rb"\s+", b"", content)
    if not stripped:
        return None
    padding = (-len(stripped)) % 4
    stripped += b"=" * padding
    try:
        decoded = base64.b64decode(stripped, validate=True)
    except Exception:
        return None
    text = decoded.decode("utf-8", errors="ignore")
    printable_ratio = sum(ch.isprintable() or ch.isspace() for ch in text) / max(len(text), 1)
    if printable_ratio < 0.8:
        return None
    return text


def normalise_name(name: str) -> str:
    cleaned = re.sub(r"\s+", " ", name.strip())
    if cleaned:
        return cleaned
    return hashlib.md5(name.encode()).hexdigest()[:8]


def merge_proxies(proxy_lists: Iterable[Proxy]) -> List[Proxy]:
    deduped: Dict[str, Proxy] = {}
    for proxy in proxy_lists:
        key = f"{proxy.type}:{proxy.server}:{proxy.port}:{proxy.data.get('uuid', proxy.data.get('password', ''))}"
        if key in deduped:
            existing = deduped[key]
            if len(proxy.name) < len(existing.name):
                deduped[key] = dataclasses.replace(proxy, latency_ms=existing.latency_ms)
        else:
            deduped[key] = proxy
    logging.info("Merged to %d unique proxies", len(deduped))
    return list(deduped.values())


def parse_subscription(content: str) -> List[Proxy]:
    if "proxies:" in content:
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            logging.warning("Unable to parse YAML subscription: %s", exc)
            data = None
        proxies_raw = data.get("proxies", []) if isinstance(data, dict) else []
        proxies: List[Proxy] = []
        for item in proxies_raw:
            if not isinstance(item, dict):
                continue
            type_ = item.get("type")
            if type_ not in SUPPORTED_TYPES:
                continue
            name = normalise_name(item.get("name", f"{type_}-{item.get('server', '')}"))
            server = item.get("server")
            port = item.get("port")
            if not server or not port:
                continue
            extra = {k: v for k, v in item.items() if k not in {"name", "type", "server", "port"}}
            proxies.append(Proxy(name=name, type=type_, server=str(server), port=int(port), data=extra))
        return proxies

    proxies: List[Proxy] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        proxy = parse_share_link(line)
        if proxy:
            proxies.append(proxy)
    return proxies


def parse_share_link(link: str) -> Optional[Proxy]:
    if link.startswith("vmess://"):
        return parse_vmess(link)
    if link.startswith("vless://"):
        return parse_vless(link)
    if link.startswith("trojan://"):
        return parse_trojan(link)
    if link.startswith("ss://"):
        return parse_ss(link)
    return None


def parse_vmess(link: str) -> Optional[Proxy]:
    payload = link[len("vmess://"):]
    try:
        missing = (-len(payload)) % 4
        payload += "=" * missing
        data = json.loads(base64.b64decode(payload).decode("utf-8"))
    except Exception as exc:
        logging.debug("Failed to parse vmess: %s", exc)
        return None
    server = data.get("add")
    port = data.get("port")
    uuid = data.get("id")
    if not server or not port or not uuid:
        return None
    name = normalise_name(data.get("ps", f"vmess-{server}"))
    extra: Dict[str, Any] = {
        "uuid": uuid,
        "alterId": int(data.get("aid", 0) or 0),
        "cipher": data.get("scy", "auto"),
        "tls": data.get("tls") == "tls",
        "udp": True,
    }
    network = data.get("net", "tcp")
    extra["network"] = network
    if network == "ws":
        ws_opts: Dict[str, Any] = {"path": data.get("path", "/")}
        host = data.get("host")
        if host:
            ws_opts["headers"] = {"Host": host}
        extra["ws-opts"] = ws_opts
    if data.get("sni"):
        extra["servername"] = data["sni"]
    return Proxy(name=name, type="vmess", server=str(server), port=int(port), data=extra)


def parse_vless(link: str) -> Optional[Proxy]:
    parsed = urlparse(link)
    if not parsed.hostname or not parsed.port:
        return None
    params = parse_qs(parsed.query)
    name = normalise_name(unquote(parsed.fragment) or parsed.hostname)
    security = params.get("security", ["none"])[0]
    network = params.get("type", [params.get("network", ["tcp"])[0]])
    extra: Dict[str, Any] = {
        "uuid": parsed.username or "",
        "flow": params.get("flow", [None])[0] or None,
        "network": network,
        "udp": True,
    }
    if security in {"tls", "reality"}:
        extra["tls"] = True
        if params.get("sni"):
            extra["servername"] = params["sni"][0]
    if network == "ws":
        ws_opts: Dict[str, Any] = {"path": params.get("path", ["/"])[0]}
        host = params.get("host")
        if host:
            ws_opts["headers"] = {"Host": host[0]}
        extra["ws-opts"] = ws_opts
    extra = {k: v for k, v in extra.items() if v not in (None, "")}
    if not extra.get("uuid"):
        return None
    return Proxy(name=name, type="vless", server=parsed.hostname, port=parsed.port, data=extra)


def parse_trojan(link: str) -> Optional[Proxy]:
    parsed = urlparse(link)
    if not parsed.hostname or not parsed.port or not parsed.username:
        return None
    params = parse_qs(parsed.query)
    name = normalise_name(unquote(parsed.fragment) or parsed.hostname)
    extra: Dict[str, Any] = {
        "password": parsed.username,
        "sni": params.get("sni", [None])[0] or params.get("peer", [None])[0],
        "udp": True,
    }
    if params.get("alpn"):
        extra["alpn"] = params["alpn"][0].split(",")
    extra = {k: v for k, v in extra.items() if v}
    return Proxy(name=name, type="trojan", server=parsed.hostname, port=parsed.port, data=extra)


def parse_ss(link: str) -> Optional[Proxy]:
    # Shadowsocks share links come in two forms: base64 encoded or plain.
    body = link[len("ss://"):]
    fragment = ""
    if "#" in body:
        body, fragment = body.split("#", 1)
    fragment = unquote(fragment)
    if "@" not in body:
        try:
            missing = (-len(body)) % 4
            body_padded = body + "=" * missing
            decoded = base64.b64decode(body_padded).decode("utf-8")
        except Exception:
            return None
    else:
        decoded = body
    if "@" not in decoded or ":" not in decoded:
        return None
    method_password, server_part = decoded.split("@", 1)
    if ":" not in method_password:
        return None
    method, password = method_password.split(":", 1)
    if ":" not in server_part:
        return None
    server, port_str = server_part.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError:
        return None
    name = normalise_name(fragment or server)
    extra = {"cipher": method, "password": password, "udp": True}
    return Proxy(name=name, type="ss", server=server, port=port, data=extra)


async def measure_latency(proxy: Proxy, timeout: float = DEFAULT_TEST_TIMEOUT) -> Optional[float]:
    start = time.perf_counter()
    try:
        await asyncio.wait_for(asyncio.open_connection(proxy.server, proxy.port), timeout=timeout)
    except Exception:
        return None
    return (time.perf_counter() - start) * 1000


async def evaluate_proxies(proxies: Sequence[Proxy], concurrency: int = 20) -> List[Proxy]:
    semaphore = asyncio.Semaphore(concurrency)

    async def worker(proxy: Proxy) -> Proxy:
        async with semaphore:
            latency = await measure_latency(proxy)
            proxy.latency_ms = latency
            if latency is None:
                logging.debug("Proxy %s failed latency test", proxy.name)
            else:
                logging.debug("Proxy %s latency: %.1f ms", proxy.name, latency)
            return proxy

    return await asyncio.gather(*(worker(proxy) for proxy in proxies))


def build_proxy_groups(proxy_names: List[str]) -> List[Dict[str, Any]]:
    base_select = "🚀 节点选择"
    auto_group = "📶 自动选择"
    fallback_group = "🛡️ 故障转移"
    groups: List[Dict[str, Any]] = [
        {
            "name": base_select,
            "type": "select",
            "proxies": [auto_group, fallback_group, "DIRECT"],
        },
        {
            "name": auto_group,
            "type": "url-test",
            "url": "https://www.gstatic.com/generate_204",
            "interval": 600,
            "tolerance": 50,
            "proxies": proxy_names,
        },
        {
            "name": fallback_group,
            "type": "fallback",
            "url": "https://cp.cloudflare.com",
            "interval": 600,
            "proxies": proxy_names,
        },
    ]

    service_groups = {
        "YouTube": "📺 YouTube",
        "Netflix": "🎬 Netflix",
        "ChatGPT": "🤖 ChatGPT",
        "Cloudflare": "☁️ Cloudflare",
        "Global": "🌍 国外流量",
    }

    for service, display_name in service_groups.items():
        groups.append(
            {
                "name": display_name,
                "type": "select",
                "proxies": [auto_group, base_select, fallback_group, "DIRECT"],
            }
        )

    groups.append(
        {
            "name": "🌐 手动切换",
            "type": "select",
            "proxies": proxy_names + ["DIRECT"],
        }
    )

    return groups


def build_rules() -> List[str]:
    return [
        "DOMAIN-SUFFIX,youtube.com,📺 YouTube",
        "DOMAIN-SUFFIX,googlevideo.com,📺 YouTube",
        "DOMAIN-KEYWORD,netflix,🎬 Netflix",
        "DOMAIN-SUFFIX,netflix.com,🎬 Netflix",
        "DOMAIN-SUFFIX,nflxvideo.net,🎬 Netflix",
        "DOMAIN-KEYWORD,chatgpt,🤖 ChatGPT",
        "DOMAIN-SUFFIX,openai.com,🤖 ChatGPT",
        "DOMAIN-SUFFIX,ai.com,🤖 ChatGPT",
        "DOMAIN-SUFFIX,cloudflare.com,☁️ Cloudflare",
        "DOMAIN-SUFFIX,cloudflare-dns.com,☁️ Cloudflare",
        "GEOIP,CN,DIRECT",
        "MATCH,🌍 国外流量",
    ]


def build_configuration(proxies: Sequence[Proxy]) -> Dict[str, Any]:
    proxy_dicts = [proxy.to_clash_dict() for proxy in proxies]
    proxy_names = [proxy.name for proxy in proxies]
    config = {
        "port": 7890,
        "socks-port": 7891,
        "mixed-port": 7892,
        "allow-lan": False,
        "mode": "Rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": proxy_dicts,
        "proxy-groups": build_proxy_groups(proxy_names),
        "rules": build_rules(),
    }
    return config


def write_yaml(config: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        yaml.dump(config, fh, allow_unicode=True, sort_keys=False)
    logging.info("Wrote configuration to %s", path)


def load_all_proxies(urls: Sequence[str]) -> List[Proxy]:
    proxies: List[Proxy] = []
    for url in urls:
        try:
            content = fetch_content(url)
        except Exception as exc:
            logging.warning("Failed to fetch %s: %s", url, exc)
            continue
        proxies.extend(parse_subscription(content))
    logging.info("Loaded %d proxies from subscriptions", len(proxies))
    return merge_proxies(proxies)


def filter_by_latency(proxies: Sequence[Proxy], threshold_ms: float) -> List[Proxy]:
    filtered = [proxy for proxy in proxies if proxy.latency_ms is not None and proxy.latency_ms <= threshold_ms]
    logging.info(
        "Filtered proxies: %d of %d within %.0f ms",
        len(filtered),
        len(proxies),
        threshold_ms,
    )
    return filtered


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate Clash subscriptions")
    parser.add_argument("--output", type=Path, default=Path("generated/clash.yaml"))
    parser.add_argument("--threshold", type=float, default=LATENCY_THRESHOLD_MS)
    parser.add_argument("--max-proxies", type=int, default=200, help="Limit number of proxies to include after filtering")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    log_setup(args.verbose)
    proxies = load_all_proxies(SUBSCRIPTION_URLS)
    if not proxies:
        logging.error("No proxies were loaded from subscriptions")
        return 1

    logging.info("Testing latency for %d proxies", len(proxies))
    evaluated = asyncio.run(evaluate_proxies(proxies))
    filtered = filter_by_latency(evaluated, args.threshold)
    if not filtered:
        logging.error("No proxies passed the latency threshold")
        return 2
    filtered.sort(key=lambda p: p.latency_ms or float("inf"))
    if args.max_proxies > 0:
        filtered = filtered[: args.max_proxies]

    config = build_configuration(filtered)
    write_yaml(config, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
