<div align="center">

# nmap-mcp

### nmap を構造化 JSON で LLM から叩く MCP サーバー

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?style=flat&logo=typescript&logoColor=white)](src/index.ts)
[![Node.js](https://img.shields.io/badge/Node.js-%E2%89%A520-339933?style=flat&logo=node.js&logoColor=white)](package.json)
[![Nmap](https://img.shields.io/badge/Nmap-7%2B-4A85C3?style=flat)](https://nmap.org/)
[![MCP](https://img.shields.io/badge/MCP-stdio-6E56CF?style=flat)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)

**LAN 内デバイス発見・ポートスキャン・サービス検出を構造化レスポンスで。**

---

</div>

## 概要

nmap を `-oX -` で必ず XML 出力させ、`fast-xml-parser` で JSON に正規化する。LLM が nmap の冗長な text 出力をパースする必要がなく、アドレス・ホスト名・ポート・サービス・OS マッチ・NSE スクリプト結果が全て構造化。

## 特徴

| アクション | 用途 |
|---|---|
| `discover` | `-sn` によるホスト発見のみ（LAN 内の生きてるデバイス列挙） |
| `scan` | ポートスキャン。`ports="22,80,443"` / `top_ports=100` 等で対象指定。`service_detect` / `script` / `os_detect` を orthogonal に追加可 |
| `services` | `scan` + `-sV` + `--script default` ショートカット |
| `os_detect` | `-O -sV`（admin/root 権限が必要） |
| `run` | 生 args の escape hatch。自動で `-oX -` を付け、XML 解析も試行 |
| `version` | `nmap --version` |

## インストール

nmap を別途インストールする必要がある（Windows: [nmap.org/download](https://nmap.org/download.html)）。

```bash
git clone https://github.com/cUDGk/nmap-mcp.git
cd nmap-mcp && npm install && npm run build
```

## 使い方

```bash
claude mcp add nmap -- node C:/Users/user/Desktop/nmap-mcp/dist/index.js
```

### 環境変数

| 変数 | デフォルト | 用途 |
|---|---|---|
| `NMAP_PATH` | Win: `C:/Program Files (x86)/Nmap/nmap.exe`, other: `nmap` | nmap 実行ファイル |
| `NMAP_TIMEOUT` | `600000` | 単一呼び出しのタイムアウト (ms) |

### 呼び出し例

LAN 内ホスト発見:

```json
{"action": "discover", "target": "192.168.1.0/24"}
```

特定ホストの TCP サービス検出:

```json
{"action": "services", "target": "scanme.nmap.org",
 "ports": "1-1000", "timing": 4, "open_only": true}
```

SYN スキャン + HTTP 関連 NSE:

```json
{"action": "scan", "target": "192.168.1.10",
 "tcp_syn": true, "ports": "80,443,8080",
 "script": "http-title,http-headers",
 "timing": 4}
```

## レスポンス形式

```json
{
  "stats": { "hosts_total": 5, "hosts_up": 3, "elapsed": "2.34" },
  "hosts": [
    {
      "status": {"state": "up"},
      "addresses": [{"addr": "192.168.1.10", "type": "ipv4"}],
      "hostnames": [{"name": "router.lan", "type": "PTR"}],
      "ports": [
        {"protocol": "tcp", "port": 22, "state": "open",
         "service_name": "ssh", "service_product": "OpenSSH"}
      ],
      "os_matches": [{"name": "Linux 4.x", "accuracy": 95}]
    }
  ]
}
```

## セキュリティ / 合法性

nmap は**自分が管理してない** ネットワークに対して使うと法的問題になる事がある。このサーバーは LAN 内の自分の機器・`scanme.nmap.org` のようなテスト用ホストなど、**許可されたスキャン対象にのみ使う**事。SYN スキャン (`tcp_syn: true`) と OS 検出 (`os_detect: true`) は OS によって管理者権限が必要。

## Attribution

- [Nmap](https://nmap.org/) — Network Mapper
- [fast-xml-parser](https://github.com/NaturalIntelligence/fast-xml-parser)
- [Model Context Protocol](https://modelcontextprotocol.io/)

## ライセンス

MIT License © 2026 cUDGk — 詳細は [LICENSE](LICENSE) を参照。
