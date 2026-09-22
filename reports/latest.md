# Shadowrocket Safe Rules — PASS

- Time (UTC): `2026-09-22T08:38:04+00:00`
- Sources checked: **27**
- Total active rules: **123,622**
- New DIRECT/PROXY exact conflicts: **0**
- Existing exact conflicts: **43**

## Sources

| Source | Policy | Rules | SHA-256 |
|---|---:|---:|---|
| Lan | DIRECT | 140 | `1287e092eb99dd9d…` |
| WeChat | DIRECT | 33 | `0f4c3c2d94ca45e4…` |
| MeiTuan | DIRECT | 7 | `6abcbfd2fcf6c66b…` |
| AliPay | DIRECT | 21 | `7b220f98eb4b21f7…` |
| Claude | PROXY | 3 | `e22906098a08537b…` |
| OpenAI | PROXY | 35 | `413c11ed079810aa…` |
| Gemini | PROXY | 13 | `605702efe5aec5ed…` |
| Copilot | PROXY | 51 | `bbe6a1043e2cc318…` |
| AppleNews | PROXY | 2 | `2ebd35c43a58cc28…` |
| iCloudPrivateRelay | PROXY | 6 | `bf918251648db75d…` |
| Google | PROXY | 698 | `1bfbf77041fda827…` |
| YouTube | PROXY | 190 | `121e30910b3aa545…` |
| Telegram | PROXY | 40 | `43a22d2da5cd8813…` |
| Twitter | PROXY | 33 | `371a1ead914bfa4f…` |
| Facebook | PROXY | 570 | `02969a9cf7cf0ec1…` |
| Instagram | PROXY | 4 | `0d97aa6e4a5a0993…` |
| TikTok | PROXY | 32 | `672a4bf5b8bfbc80…` |
| Netflix | PROXY | 1,157 | `6c0043676e2a34c8…` |
| Disney | PROXY | 173 | `851646ffda40afd7…` |
| HBO | PROXY | 49 | `c6482a681cda4a61…` |
| Spotify | PROXY | 30 | `38ec3e72e9bf0a34…` |
| GlobalMedia | PROXY | 1,021 | `b14d04fd1badc138…` |
| GlobalMedia_Domain | PROXY | 1,311 | `c3f867d4a594ee4e…` |
| Proxy | PROXY | 131 | `33a6361c81768e13…` |
| Proxy_Domain | PROXY | 6,793 | `06a22d3a4c88c837…` |
| ChinaMaxNoIP | DIRECT | 125 | `a38332c2745a95fe…` |
| ChinaMaxNoIP_Domain | DIRECT | 110,954 | `0cd2cba3be71df25…` |

## Fail-closed behavior

If this run fails, `rules/` and `state/manifest.json` are not published by the validator.
The phone therefore continues using the last approved mirror.
