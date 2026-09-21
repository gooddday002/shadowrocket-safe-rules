# shadowrocket-safe-rules

Validated Shadowrocket rule mirror with **fail-closed automatic updates**.

This repository is intentionally public and contains **only public rule data and validation code**.
It must never contain private Shadowrocket configs, node URLs, subscriptions, MITM CA/private keys,
banking logs, account identifiers, or personal override rules.

## What happens automatically

Every day, and whenever the validator/workflow changes:

1. Pull 27 selected Shadowrocket rule sources from Blackmatrix7.
2. Download only from an explicit HTTPS host/path allowlist.
3. Validate rule syntax and allowed rule types.
4. Reject rule files that are unexpectedly small.
5. Reject excessive duplicates.
6. Require `no-resolve` on IP-CIDR/IP6-CIDR rules.
7. Compare rule counts with the last approved snapshot.
8. Reject large unexpected drops (>35%) or growth (>80%) for established lists.
9. Detect newly introduced exact DIRECT/PROXY domain conflicts.
10. Protect critical PROXY domains such as Claude, Anthropic, OpenAI, ChatGPT, Google,
    YouTube, Telegram, X/Twitter, TikTok and Netflix from appearing in DIRECT upstream rules.
11. Publish `rules/` only after **all checks pass**.

If any blocking check fails, the workflow exits without publishing new rules.
Shadowrocket therefore continues using the **last approved snapshot**.

## Simple status for the owner

- Green GitHub Actions run = no action needed.
- Red GitHub Actions run = **do not change the phone**. The previous approved rules remain published.
- Open `reports/latest.md` to see the most recent approved snapshot.
- Open the failed Actions run summary to see why an update was rejected.

## Update schedule

The workflow runs daily at **03:17 UTC** and can also be started manually from GitHub Actions.

## Repository layout

```
.
├── .github/workflows/update-rules.yml
├── sources.json
├── validator.py
├── tests/test_validator.py
├── rules/                 # only validated mirrored rules
├── state/manifest.json    # last approved hashes/counts/conflict baseline
└── reports/
    ├── latest.md
    └── latest.json
```

## Shadowrocket URLs

After the first successful workflow run, use this repository's Raw URLs instead of the upstream
Blackmatrix7 URLs.

Example:

```
RULE-SET,https://raw.githubusercontent.com/gooddday002/shadowrocket-safe-rules/main/rules/blackmatrix7/Claude/Claude.list,PROXY,update-interval=86400
RULE-SET,https://raw.githubusercontent.com/gooddday002/shadowrocket-safe-rules/main/rules/blackmatrix7/OpenAI/OpenAI.list,PROXY,update-interval=86400
RULE-SET,https://raw.githubusercontent.com/gooddday002/shadowrocket-safe-rules/main/rules/blackmatrix7/Proxy/Proxy.list,PROXY,update-interval=86400
DOMAIN-SET,https://raw.githubusercontent.com/gooddday002/shadowrocket-safe-rules/main/rules/blackmatrix7/Proxy/Proxy_Domain.list,PROXY,update-interval=86400
RULE-SET,https://raw.githubusercontent.com/gooddday002/shadowrocket-safe-rules/main/rules/blackmatrix7/ChinaMaxNoIP/ChinaMaxNoIP.list,DIRECT,update-interval=86400
DOMAIN-SET,https://raw.githubusercontent.com/gooddday002/shadowrocket-safe-rules/main/rules/blackmatrix7/ChinaMaxNoIP/ChinaMaxNoIP_Domain.list,DIRECT,update-interval=86400
```

Do **not** point the phone at this mirror until the first workflow has completed successfully and
`state/manifest.json` exists.

## Security boundaries

This validator reduces supply-chain risk; it does not make upstream data intrinsically trustworthy.

Residual risks include:

- A malicious upstream change that stays within all configured thresholds.
- Semantic conflicts more complex than exact normalized domain-pattern conflicts.
- Shadowrocket runtime behavior that differs from static rule semantics.
- GitHub account/repository compromise.

For the higher-risk routing boundary, the phone configuration should still keep:

- explicit critical-service PROXY rules before broad lists;
- `GEOIP,CN,DIRECT,no-resolve`;
- `FINAL,PROXY`;
- system DNS fallback disabled;
- UDP unsupported behavior set to REJECT.

## Development

Run locally:

```bash
python3 -m unittest discover -s tests -v
python3 validator.py --config sources.json --repo-root . --report /tmp/validation-report.md
```

The unit suite includes a regression check proving that a failed validation does not overwrite an
already published rule file.
