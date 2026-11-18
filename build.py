import argparse
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import platform
import subprocess
import tarfile
from urllib.request import urlopen
import zipfile


ROOT = Path(__file__).resolve().parent
RAW = "https://raw.githubusercontent.com/"
RELEASE = "https://github.com/"
IT = RELEASE + "itdoginfo/allow-domains/releases/latest/download/"
DAV = RAW + "Davoyan/xray-routing/main/release/"
ROS_SITE = RELEASE + "hydraponique/roscomvpn-geosite/releases/latest/download/"
ROS_IP = RELEASE + "hydraponique/roscomvpn-geoip/releases/latest/download/"
LEG = RAW + "legiz-ru/mihomo-rule-sets/main/"
SB = RAW + "legiz-ru/sb-rule-sets/main/"
IT_IP = {
    "from-russia": "cloudflare cloudfront digitalocean discord hetzner meta ovh telegram twitter",
    "in-russia": "roblox google-meet",
}
SOURCES = {
    "it-site": IT + "geosite.dat",
    "dav-site": DAV + "geosite.dat",
    "ros-site": ROS_SITE + "geosite.dat",
    "dav-ip": DAV + "geoip.dat",
    "ros-ip": ROS_IP + "geoip.dat",
    "nsfw": LEG + "oisd/nsfw_small.yaml",
    "discord-voice": LEG + "other/discord-voice-ip-list.mrs",
    "rknasnblock": LEG + "ru-bundle/rknasnblock.mrs",
    "wli": LEG + "other/wli.mrs",
    "telegram-extra": RAW + "Davoyan/mihomo-rule-sets/main/domains/additional-telegram-ips.yaml",
    "viber": SB + "viber_aws_ip.srs",
}
for names in IT_IP.values():
    for tag in names.split():
        SOURCES[f"it-ip-{tag}"] = IT + tag.replace("-", "_") + "_ipcidr.mrs"

WINDOWS_TOOLS = {
    "mihomo": ("MetaCubeX/mihomo", "v1.19.34", "mihomo-windows-amd64-v1-v1.19.34.zip",
               "703e325bfeee582f874b06d054eaae55ab7c194645d1835411685aafa85da5ea"),
    "sing-box": ("SagerNet/sing-box", "v1.14.4", "sing-box-1.14.4-windows-amd64.zip",
                 "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df"),
    "xray": ("XTLS/Xray-core", "v26.11.9", "Xray-windows-64.zip",
             "1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d"),
}


LINUX_TOOLS = {
    "mihomo": ("MetaCubeX/mihomo", "v1.19.34", "mihomo-linux-amd64-v1-v1.19.34.gz",
               "0c07340a01408d033dda4088ea2a4c1e4d82aeed7b2f84f7c046e93b6ff3290c"),
    "sing-box": ("SagerNet/sing-box", "v1.14.4", "sing-box-1.14.4-linux-amd64.tar.gz",
                 "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"),
    "xray": ("XTLS/Xray-core", "v26.11.9", "Xray-linux-64.zip",
             "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82"),
}


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def download(url):
    with urlopen(url, timeout=60) as response:
        return response.read()


def load_tool(entry):
    name, (repo, tag, asset, expected) = entry
    url = f"{RELEASE}{repo}/releases/download/{tag}/{asset}"
    blob = download(url)
    if digest(blob) != expected:
        raise ValueError(f"Unexpected digest for {name}")
    executable = name + ".exe" if os.name == "nt" else name
    target = ROOT / "tools" / executable
    if asset.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            members = [member for member in archive.namelist()
                       if Path(member).name == executable]
            if len(members) != 1:
                raise ValueError(f"Unexpected ZIP layout for {name}")
            binary = archive.read(members[0])
    elif asset.endswith(".tar.gz"):
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            members = [member for member in archive.getmembers()
                       if member.isfile() and Path(member.name).name == executable]
            if len(members) != 1:
                raise ValueError(f"Unexpected tar layout for {name}")
            with archive.extractfile(members[0]) as stream:
                binary = stream.read()
    else:
        binary = gzip.decompress(blob)
    target.write_bytes(binary)
    if os.name != "nt":
        target.chmod(0o755)
    return name, target


def read_varint(blob, offset):
    value = 0
    for shift in range(0, 70, 7):
        byte = blob[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError("Invalid varint")


def fields(blob):
    offset = 0
    while offset < len(blob):
        key, offset = read_varint(blob, offset)
        value, offset = read_varint(blob, offset)
        if key & 7 == 2:
            end = offset + value
            if end > len(blob):
                raise ValueError("Truncated protobuf field")
            yield key >> 3, blob[offset:end]
            offset = end
        elif key & 7 == 0:
            yield key >> 3, value
        else:
            raise ValueError(f"Unsupported wire type: {key & 7}")


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    return varint((number << 3) | 2) + varint(len(value)) + value


def decode_dat(blob, is_ip):
    result = {}
    for key, record in fields(blob):
        if key != 1:
            raise ValueError(f"Unexpected DAT field: {key}")
        header = dict(fields(record))
        name = header[1].decode().lower()
        if is_ip and header.get(3, 0):
            raise ValueError(f"Inverse IP category: {name}")
        entries = set()
        for number, item in fields(record):
            if number != 2:
                continue
            values = dict(fields(item))
            if is_ip:
                entries.add(ipaddress.ip_network((ipaddress.ip_address(values[1]),
                                                  values.get(2, 0))))
            else:
                attrs = tuple(sorted(value for kind, value in fields(item) if kind == 3))
                entries.add((values.get(1, 0), values[2].decode(), attrs))
        if not entries or name in result:
            raise ValueError(f"Empty or repeated category: {name}")
        result[name] = entries
    return result


def encode_dat(categories, is_ip):
    chunks = []
    for name, entries in sorted(categories.items()):
        def encode_entry(entry):
            if is_ip:
                return field(1, entry.network_address.packed) + field(2, entry.prefixlen)
            kind, value, attrs = entry
            return (field(1, kind) + field(2, value.encode()) +
                    b"".join(field(3, attr) for attr in attrs))

        order = str if is_ip else None
        records = b"".join(field(2, encode_entry(entry)) for entry in sorted(entries, key=order))
        chunks.append(field(1, field(1, name.upper().encode()) + records))
    return b"".join(chunks)


def run(tool, *args, env=None):
    outcome = subprocess.run([str(tool), *map(str, args)], capture_output=True,
                             text=True, encoding="utf-8", errors="replace", env=env)
    if outcome.returncode:
        raise RuntimeError(f"{tool.name} {args}:\n{outcome.stdout}\n{outcome.stderr}")


def domain_key(entry):
    kind, value, _ = entry
    return kind, value if kind == 1 else value.lower()


def make_domains(blobs):
    it = decode_dat(blobs["it-site"], False)
    dav = decode_dat(blobs["dav-site"], False)
    ros = decode_dat(blobs["ros-site"], False)
    groups = {
        "from-russia": "anime block geoblock news nsfw trackers meta tiktok twitter youtube "
                       "discord telegram hodca banned twitch google-ai github",
        "to-russia": "russia-outside",
        "in-russia": "google-meet google-play roblox category-ru apple epicgames escapefromtarkov "
                     "faceit microsoft origin pinterest riot steam wl-ru push",
        "private": "private",
        "ip-checkers": "category-ip-geo-detect",
        "block": "category-ads twitch-ads win-spy",
    }
    tags = {tag for names in groups.values() for tag in names.split()}
    it_sources = {"nsfw": "porn", "trackers": "hdrezka"}
    it_entries = {tag: set(it[it_sources.get(tag, tag)]) for tag in tags
                  if it_sources.get(tag, tag) in it}
    for tag in "cloudflare cloudfront digitalocean hetzner ovh".split():
        it_entries["hodca"].update(it[tag])
    it_keys = {domain_key(entry) for entries in it_entries.values() for entry in entries}
    result = {tag: set(it_entries.get(tag, ())) for tag in tags}
    removed = {}
    for tag in dav:
        filtered = {entry for entry in dav[tag] if domain_key(entry) not in it_keys}
        result[tag].update(filtered)
        removed[tag] = len(dav[tag]) - len(filtered)
    ros_targets = {
        "category-geoblock-ru": "geoblock", "torrent": "trackers",
        "google-deepmind": "google-ai", "whitelist": "wl-ru",
    }
    for tag in ros:
        result[ros_targets.get(tag, tag)].update(ros[tag])

    nsfw_lines = blobs["nsfw"].decode().splitlines()
    for line in nsfw_lines:
        if line.strip() == "payload:" or not line.strip():
            continue
        match = re.fullmatch(r"\s*- '\+\.([^']+)'\s*", line)
        if not match:
            raise ValueError(f"Unsupported NSFW rule: {line}")
        result["nsfw"].add((2, match[1], ()))

    # Merge equivalent matchers while preserving their original attribute tags.
    for tag, entries in result.items():
        merged = {}
        for entry in entries:
            merged.setdefault(domain_key(entry), set()).update(entry[2])
        result[tag] = {(kind, value, tuple(sorted(attrs)))
                       for (kind, value), attrs in merged.items()}
    if set(result) != tags or len(tags) != 38 or not all(result.values()):
        raise ValueError("Invalid domain category mapping")
    return result, groups, removed


def collapsed(entries):
    entries = set(entries)
    return {net for version in (4, 6) for net in ipaddress.collapse_addresses(
        net for net in entries if net.version == version)}


def make_ips(blobs, tools, work):
    dav = decode_dat(blobs["dav-ip"], True)
    ros = decode_dat(blobs["ros-ip"], True)

    def decode_mrs(key):
        source = work / (key + ".mrs")
        target = work / (key + ".txt")
        source.write_bytes(blobs[key])
        run(tools["mihomo"], "convert-ruleset", "ipcidr", "mrs", source, target)
        result = {ipaddress.ip_network(line) for line in target.read_text().splitlines() if line}
        if not result:
            raise ValueError(f"Empty MRS: {key}")
        return result

    private = ros["private"] | dav["private"]
    private.discard(ipaddress.ip_network("0.0.0.0/8"))
    raw_source = work / "viber.srs"
    viber_text = work / "viber.json"
    raw_source.write_bytes(blobs["viber"])
    run(tools["sing-box"], "rule-set", "decompile", raw_source, "-o", viber_text)
    viber = set()
    for rule in json.loads(viber_text.read_text())["rules"]:
        if set(rule) != {"ip_cidr"}:
            raise ValueError(f"Unexpected Viber rule: {rule}")
        cidrs = rule["ip_cidr"]
        if isinstance(cidrs, str):
            cidrs = [cidrs]
        viber.update(ipaddress.ip_network(net) for net in cidrs)
    extra_telegram = set()
    for line in blobs["telegram-extra"].decode().splitlines():
        if not line.strip() or line.strip() == "payload:":
            continue
        match = re.fullmatch(r"\s*-\s*IP-CIDR(?:6)?,([^,\s]+)(?:,no-resolve)?\s*", line)
        if not match:
            raise ValueError(f"Unexpected Telegram rule: {line}")
        extra_telegram.add(ipaddress.ip_network(match[1], strict=False))

    result = {tag: decode_mrs("it-ip-" + tag)
              for names in IT_IP.values() for tag in names.split()}
    result["discord"].update(decode_mrs("discord-voice"))
    result["telegram"].update(extra_telegram)
    result.update({
        "viber_aws_ip": viber,
        "rknasnblock": decode_mrs("rknasnblock"),
        "apple": dav["apple"],
        "whitelist": ros["whitelist"] | dav["wl-ru"] | decode_mrs("wli"),
        "direct": ros["direct"] | dav["ru"],
        "private": private,
    })
    groups = {
        "from-russia": IT_IP["from-russia"] + " viber_aws_ip rknasnblock",
        "in-russia": IT_IP["in-russia"] + " apple whitelist direct",
        "block": "private",
    }
    if len(result) != 17 or not all(result.values()):
        raise ValueError("Invalid IP category mapping")
    if set(result) != {tag for names in groups.values() for tag in names.split()}:
        raise ValueError("IP groups do not match the category set")
    return result, groups


def emit_mihomo(out, work, tool, domains, ips, domain_groups, ip_groups):
    providers = {}

    def register(path, behavior, fmt):
        relative = path.relative_to(out).as_posix()
        key = relative.replace("/", "-").replace(".", "-")
        providers[key] = {"type": "file", "behavior": behavior,
                          "format": fmt, "path": "./" + relative}

    def compile_mrs(path, behavior, entries):
        path.parent.mkdir(parents=True, exist_ok=True)
        text = work / "in.txt"
        text.write_text("\n".join(sorted(map(str, entries))) + "\n", encoding="utf-8")
        run(tool, "convert-ruleset", behavior, "text", text, path)
        check = work / "check.txt"
        run(tool, "convert-ruleset", behavior, "mrs", path, check)
        decoded = set(check.read_text(encoding="utf-8").splitlines())
        if not decoded:
            raise ValueError(f"Round trip gave empty MRS: {path}")
        if behavior == "ipcidr" and collapsed(map(ipaddress.ip_network, decoded)) != entries:
            raise ValueError(f"CIDR coverage changed: {path}")
        if behavior == "domain":
            def expanded(patterns):
                return {part for pattern in patterns for part in
                        ((pattern[2:], pattern[1:]) if pattern.startswith("+.") else (pattern,))}
            if expanded(decoded) != expanded(entries):
                mismatch = sorted(expanded(decoded) ^ expanded(entries))
                raise ValueError(f"Domain matchers changed: {path}: {mismatch[:20]}")
        register(path, behavior, "mrs")

    def collections(categories, groups):
        for name, entries in sorted(categories.items()):
            yield "categories/" + name, entries
        for name, tags in groups.items():
            yield "groups/" + name, set().union(*(categories[tag] for tag in tags.split()))
        yield "all", set().union(*categories.values())

    for name, entries in collections(domains, domain_groups):
        path = out / "mihomo" / "domain" / (name + ".mrs")
        patterns = {("+" + "." if kind == 2 else "") + value
                    for kind, value, _ in entries if kind in (2, 3)}
        if patterns:
            compile_mrs(path, "domain", patterns)
        classical = {("DOMAIN-KEYWORD" if kind == 0 else "DOMAIN-REGEX") + "," + value
                     for kind, value, _ in entries if kind in (0, 1)}
        if {kind for kind, _, _ in entries} - {0, 1, 2, 3}:
            raise ValueError(f"Unsupported domain matcher kind: {name}")
        if classical:
            target = path.with_suffix(".classical.yaml")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("payload:\n" + "".join(
                "  - " + json.dumps(rule, ensure_ascii=False) + "\n" for rule in sorted(classical)),
                encoding="utf-8")
            register(target, "classical", "yaml")
    for name, entries in collections(ips, ip_groups):
        compile_mrs(out / "mihomo" / "ipcidr" / (name + ".mrs"), "ipcidr", collapsed(entries))
    config = work / "mihomo-check.yaml"
    config.write_text(json.dumps({
        "rule-providers": providers,
        "rules": [f"RULE-SET,{key},DIRECT" for key in providers] + ["MATCH,DIRECT"],
    }), encoding="utf-8")
    run(tool, "-t", "-d", out, "-f", config)


def validate_xray(out, work, tool, domains, ips):
    config = work / "xray-check.json"
    rules = [{"type": "field", "outboundTag": "direct", key: [prefix + name]}
             for key, prefix, entries in [("domain", "geosite:", domains), ("ip", "geoip:", ips)]
             for name in sorted(entries)]
    config.write_text(json.dumps({
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        "routing": {"rules": rules},
    }), encoding="utf-8")
    run(tool, "run", "-test", "-config", config,
        env={**os.environ, "XRAY_LOCATION_ASSET": str(out)})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    output = parser.parse_args().output.resolve()
    if output.parent != ROOT:
        raise ValueError("Output must be an immediate child of the build directory")
    import tempfile

    work = ROOT / "work"
    if output.exists():
        raise FileExistsError(f"Output path already exists: {output}")
    for folder in (ROOT / "tools", work):
        folder.mkdir(exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="staging-", dir=ROOT))

    print("Resolving latest sources and downloading verified tools", flush=True)
    tool_releases = {"Windows": WINDOWS_TOOLS, "Linux": LINUX_TOOLS}.get(platform.system())
    if tool_releases is None or platform.machine().lower() not in ("amd64", "x86_64"):
        raise ValueError("The build tools require x86-64 Windows or Linux")
    with ThreadPoolExecutor(max_workers=12) as pool:
        tool_tasks = [pool.submit(load_tool, entry) for entry in tool_releases.items()]
        def resolve(url):
            if url.startswith(RAW):
                owner, repo, branch, path = url.removeprefix(RAW).split("/", 3)
                ref = subprocess.check_output(
                    ["git", "ls-remote", f"{RELEASE}{owner}/{repo}.git", f"refs/heads/{branch}"],
                    text=True, timeout=45,
                ).split()[0]
                return f"{RAW}{owner}/{repo}/{ref}/{path}"
            repo, asset = url.removeprefix(RELEASE).split("/releases/latest/download/")
            with urlopen(f"{RELEASE}{repo}/releases/latest", timeout=45) as response:
                release = response.url
            if "/releases/tag/" not in release:
                raise ValueError(f"Latest release unavailable: {repo}")
            return release.replace("/releases/tag/", "/releases/download/") + "/" + asset

        bases = {url.rsplit("/releases/latest/download/", 1)[0] + "/releases/latest/download/_"
                 if "/releases/latest/download/" in url else RAW + "/".join(
                     url.removeprefix(RAW).split("/")[:3]) + "/_"
                 for url in SOURCES.values()}
        resolved = dict(zip(sorted(bases), pool.map(resolve, sorted(bases))))

        def resolve_asset(url):
            for base, pinned in resolved.items():
                if url.startswith(base[:-1]):
                    return pinned[:-1] + url[len(base) - 1:]
            raise ValueError(f"Unmapped source URL: {url}")

        source_urls = {key: resolve_asset(url) for key, url in SOURCES.items()}
        blobs = dict(zip(source_urls, pool.map(download, source_urls.values())))
        tools = dict(task.result() for task in tool_tasks)
    expected = json.loads((ROOT / "sources.json").read_text(encoding="utf-8"))
    for name, tags in expected.items():
        actual = set(decode_dat(blobs[name], name.endswith("-ip")))
        added = sorted(actual - set(tags))
        removed = sorted(set(tags) - actual)
        if added or removed:
            raise ValueError(f"{name}: added categories {added}, removed categories {removed}")
    domains, domain_groups, dav_removed = make_domains(blobs)
    ips, ip_groups = make_ips(blobs, tools, work)
    print(f"Building {len(domains)} domain and {len(ips)} IP categories", flush=True)
    for name, payload, is_ip in (("geosite", domains, False), ("geoip", ips, True)):
        path = staging / (name + ".dat")
        path.write_bytes(encode_dat(payload, is_ip))
        if decode_dat(path.read_bytes(), is_ip) != payload:
            raise ValueError(f"DAT round trip changed {name}")
    validate_xray(staging, work, tools["xray"], domains, ips)
    print("Xray config test passed. Compiling and checking MRS providers", flush=True)
    emit_mihomo(staging, work, tools["mihomo"], domains, ips, domain_groups, ip_groups)
    paths = sorted(path for path in staging.rglob("*") if path.is_file())
    manifest = {
        "sources": {name: {"url": url, "sha256": digest(blobs[name])} for name, url in source_urls.items()},
        "tools": {name: {"repository": repo, "version": tag, "archive": archive, "sha256": sha}
                  for name, (repo, tag, archive, sha) in tool_releases.items()},
        "domain_categories": {name: len(entries) for name, entries in sorted(domains.items())},
        "ip_categories": {name: {"cidr": len(entries), "collapsed_cidr": len(collapsed(entries))}
                          for name, entries in sorted(ips.items())},
        "domain_groups": {name: tags.split() for name, tags in domain_groups.items()},
        "ip_groups": {name: tags.split() for name, tags in ip_groups.items()},
        "davoyan_domain_duplicates_removed": dav_removed,
        "files": {path.relative_to(staging).as_posix(): {"sha256": digest(path.read_bytes()),
                  "bytes": path.stat().st_size} for path in paths},
    }
    (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    staging.rename(output)
    print(f"Verified and published {len(paths)} files plus manifest in {output}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        message = str(error).splitlines()[0][:500]
        # A failed download can include a signed redirect URL.
        message = re.sub(r"https?://[^\s]+", "[URL]", message)
        (ROOT / "build-error.txt").write_text(message, encoding="utf-8")
        raise SystemExit(message) from None
