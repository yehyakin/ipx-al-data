#!/usr/bin/env python3
"""ipx VPN 网段层（x4b.bin / x4b6.bin / x4b.json / LICENSE-X4B.txt）

来源：X4BNet/lists_vpn（https://github.com/X4BNet/lists_vpn），MIT License，Copyright (c) 2026 X4B (Mathew Heard)。
只用它 MIT 部分：人工整理的 VPN ASN 名单 input/vpn/ASN.txt 和人工网段 input/vpn/ips/*.txt。
它发布的 output/vpn/*.txt 是用 IPLocate ip-to-asn 库（CC BY-SA 4.0）展开 ASN 得到的，带署名相同方式共享的义务，
所以这里不直接用 output，而是用 RIPE RIS riswhois（≥10 个对等体看到的前缀）自己把 ASN 展开成网段，
和 build-dc.py 同一套路由数据。按关键字「VPN」从 IPLocate 名称匹配的那部分因此没有收。

只用于 ipx.al 报告页「C段画像」着色，不进评分。每 6 小时随 risk.yml 重建，跟随上游 main 的最新输入。
文件格式：x4b.bin 每条 12 字节小端 start,end,meta；x4b6.bin 每条 20 字节（start/end 高 64 位各两个 u32，meta）。
meta = 来源下标（x4b.json providers），按最长前缀优先。
"""
import bisect, datetime as dt, gzip, ipaddress, json, os, re, struct, sys, urllib.request

OUT = sys.argv[1] if len(sys.argv) > 1 else 'risk-data'
REPO = 'X4BNet/lists_vpn'
RAW = f'https://raw.githubusercontent.com/{REPO}/%s/'
MIN_PEERS = 10
# AS9009 M247 是普通机房，整个 ASN 当 VPN 会把非 VPN 客户一起标上（Kin 2026-11-09 同意排除）；M247 上的 NordVPN 服务器由 vpn.bin 官方服务器 IP 覆盖
EXCLUDE_ASNS = {9009}
UA = {'User-Agent': 'ipx.al data builder (https://ipx.al)'}


def get(url, timeout=120):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout).read()


def main():
    os.makedirs(OUT, exist_ok=True)
    sha = json.loads(get(f'https://api.github.com/repos/{REPO}/commits/main'))['sha']
    base = RAW % sha
    readme = get(base + 'README.md').decode('utf-8', 'replace')
    m = re.search(r'```\s*\n(MIT License.*?)```', readme, re.S)
    if not m:
        sys.exit('upstream README no longer carries the MIT license text; stop (license check)')
    lic = m.group(1).strip()
    asns = {}
    for line in get(base + 'input/vpn/ASN.txt').decode('utf-8', 'replace').splitlines():
        mm = re.match(r'\s*AS(\d+)\s*(?:#\s*(.*))?$', line)
        if mm and int(mm.group(1)) not in EXCLUDE_ASNS:
            asns[int(mm.group(1))] = re.sub(r'\s*\(https?://[^)]*\)', '', mm.group(2) or '').strip() or f'AS{mm.group(1)}'
    files = [x['name'] for x in json.loads(get(f'https://api.github.com/repos/{REPO}/contents/input/vpn/ips?ref={sha}')) if x['name'].endswith('.txt')]
    provs, items, counts = [], {4: [], 6: []}, {}

    def pid(name):
        if name not in provs:
            provs.append(name)
        return provs.index(name)

    def add(cidr, p):
        try:
            nw = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            return False
        if not nw.is_global:
            return False
        if nw.version == 4:
            items[4].append((int(nw.network_address), int(nw.broadcast_address), nw.prefixlen, p))
        else:
            if nw.prefixlen > 64:
                nw = nw.supernet(new_prefix=64)
            items[6].append((int(nw.network_address) >> 64, int(nw.broadcast_address) >> 64, nw.prefixlen, p))
        return True

    for f in files:
        name = 'X4B ' + f[:-4]
        n = sum(add(l.split('#')[0], pid(name)) for l in get(base + 'input/vpn/ips/' + f).decode('utf-8', 'replace').splitlines() if l.split('#')[0].strip())
        counts[name] = n
    for ver in (4, 6):
        raw = gzip.decompress(get(f'https://www.ris.ripe.net/dumps/riswhoisdump.IPv{ver}.gz', 300)).decode('utf-8', 'replace')
        for line in raw.splitlines():
            if not line or line[0] in '%#':
                continue
            p = line.split('\t')
            if len(p) < 3 or not p[0].isdigit() or int(p[2]) < MIN_PEERS:
                continue
            a = int(p[0])
            if a in asns and add(p[1], pid(f'AS{a} {asns[a]}')):
                counts[f'AS{a}'] = counts.get(f'AS{a}', 0) + 1
    meta = {'built': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'version': 1,
            'source': f'https://github.com/{REPO}', 'commit': sha, 'license': 'MIT', 'copyright': 'Copyright (c) 2026 X4B (Mathew Heard)',
            'excluded_asns': sorted(EXCLUDE_ASNS), 'note': 'ASN.txt + input/vpn/ips (MIT) expanded with RIPE RIS riswhois; upstream output/ (IPLocate CC BY-SA 4.0) not used',
            'asns': {str(k): v for k, v in sorted(asns.items())}, 'providers': provs, 'counts': counts}
    for ver, fn in ((4, 'x4b.bin'), (6, 'x4b6.bin')):
        it = sorted(items[ver], key=lambda x: x[2])  # 短前缀先铺，长前缀后盖
        bounds = sorted({x[0] for x in it} | {x[1] + 1 for x in it})
        owner = [None] * len(bounds)
        for x in it:
            for k in range(bisect.bisect_left(bounds, x[0]), bisect.bisect_left(bounds, x[1] + 1)):
                owner[k] = x[3]
        rows = []
        for k in range(len(bounds) - 1):
            if owner[k] is None:
                continue
            s, e = bounds[k], bounds[k + 1] - 1
            if rows and rows[-1][1] + 1 == s and rows[-1][2] == owner[k]:
                rows[-1][1] = e
            else:
                rows.append([s, e, owner[k]])
        buf = bytearray()
        for s, e, mm in rows:
            buf += struct.pack('<III', s, e, mm) if ver == 4 else struct.pack('<IIIII', s >> 32, s & 0xffffffff, e >> 32, e & 0xffffffff, mm)
        open(os.path.join(OUT, fn), 'wb').write(buf)
        meta[f'v{ver}'] = {'ranges': len(rows), ('addresses' if ver == 4 else 'slash64s'): sum(e - s + 1 for s, e, _ in rows)}
    if not meta['v4']['ranges']:
        sys.exit('x4b: empty build')
    json.dump(meta, open(os.path.join(OUT, 'x4b.json'), 'w'), ensure_ascii=False)
    open(os.path.join(OUT, 'LICENSE-X4B.txt'), 'w').write(
        'x4b.bin / x4b6.bin / x4b.json are derived from X4BNet/lists_vpn (https://github.com/X4BNet/lists_vpn), commit ' + sha + '.\n'
        'VPN ASN list and manual ranges from that project; ASN-to-prefix expansion uses RIPE RIS riswhois.\n\n' + lic + '\n')
    print(json.dumps({k: v for k, v in meta.items() if k not in ('asns', 'providers')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
