# ipx.al 风险库数据
每 6 小时由 GitHub Actions 从公开威胁情报重新构建，只保留最新一份（无历史）。
- `sources.csv`：区间、命中来源、首次出现日期（人可读）
- `risk.bin`：每条 16 字节小端 start,end,mask,first（ipx.al 线上查询用）
- `risk.json`：来源列表、条数、构建时间
- `vpn.bin` / `vpn6.bin` / `vpn.json`：ipx VPN 出口库，Mullvad、NordVPN、PIA、IVPN、Surfshark 官方公布的服务器 IP 和 iCloud 专用代理出口表，说明见 build-vpn.py
- `gf.bin` / `gf6.bin` / `gf.json` / `geofeed-urls.csv`：ipx 地理层，运营商自报的 RFC 8805 geofeed（按 RFC 9632 校验授权），说明见 build-geofeed.py
- `lease.bin` / `lease.json`：ipx 租赁段（IPv4），RIPE / APNIC / AFRINIC / LACNIC whois 库和 ARIN RDAP 里带 IPXO 租赁市场标记（mnt-by netutils-mnt 或 geofeed.ipxo.com）的登记网段，和地理层同一遍扫描，说明见 build-geofeed.py
- `dc.bin` / `dc.json` / `dc.csv`：ipx 机房段库（IPv4），云厂商官方段 + RIPE RIS 路由 + 人工机房 ASN + PeeringDB Content，说明见 build-dc.py
- `hist/<a>.bin`（按第一段八位组分片）/ `hist.bin.gz`：近 90 天移出名单的 IPv4 区间，每条 20 字节 start,end,mask,first,last；first/last 是 ipx 每 6 小时构建观测到的日期（自开始记录起），见 build-risk.py
- `risk6.bin`：IPv6 风险区间（v2：16 字节头 + 每条 40 字节，完整 128 位 start/end + mask + first；单个主机不再扩成 /64）
- `rir.bin` / `rir6.bin` / `rir.json`：五大 RIR delegated-extended 的登记日期（最后一次登记变更日）和国家（v2：16 字节文件头，每条带 delegated 国家），说明见 build-rir.py
来源与许可见 https://ipx.al/risk 。纠错请提 issue。
