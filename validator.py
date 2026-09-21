#!/usr/bin/env python3
"""
Validated Shadowrocket rule mirror.

Security model:
- Download only from explicitly allowed HTTPS hosts/path prefixes.
- Validate format, size, duplicates, and no-resolve semantics before publishing.
- Compare rule counts with the last approved manifest; large unexpected changes fail closed.
- Track DIRECT/PROXY domain conflicts and fail on newly introduced conflicts after bootstrap.
- Reject protected PROXY domains if they appear in DIRECT upstream rules.
- Stage all downloads first; write rules/state/reports only after every check passes.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import shutil
import sys
import tempfile
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ALLOWED_RULE_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD",
    "IP-CIDR", "IP-CIDR6", "IP6-CIDR", "IP-ASN",
    "GEOIP", "USER-AGENT", "URL-REGEX", "PROCESS-NAME",
    "DEST-PORT", "SRC-IP", "PROTOCOL",
}
FORBIDDEN_POLICY_TOKENS = {"DIRECT", "PROXY", "REJECT", "REJECT-DROP"}
COMMENT_PREFIXES = ("#", "//")


class ValidationError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def active_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith(COMMENT_PREFIXES)
    ]


def safe_relpath(path: str) -> str:
    p = Path(path)
    if p.is_absolute() or ".." in p.parts:
        raise ValidationError(f"unsafe output path: {path}")
    return p.as_posix()


def validate_source_url(url: str, cfg: dict) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ValidationError(f"non-HTTPS source rejected: {url}")
    if parsed.hostname not in set(cfg["global"]["allowed_hosts"]):
        raise ValidationError(f"source host not allowed: {parsed.hostname}")
    prefixes = cfg["global"].get("allowed_path_prefixes", [])
    if prefixes and not any(parsed.path.startswith(p) for p in prefixes):
        raise ValidationError(f"source path outside allowlist: {parsed.path}")


def download(url: str, cfg: dict) -> bytes:
    validate_source_url(url, cfg)
    timeout = int(cfg["global"]["timeout_seconds"])
    cap = int(cfg["global"]["max_bytes_per_source"])
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "shadowrocket-safe-rules/1.0 (+GitHub Actions)",
            "Accept": "text/plain,*/*;q=0.1",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        final_url = resp.geturl()
        validate_source_url(final_url, cfg)
        if getattr(resp, "status", 200) != 200:
            raise ValidationError(f"HTTP {getattr(resp, 'status', '?')} for {url}")
        data = resp.read(cap + 1)
    if len(data) > cap:
        raise ValidationError(f"source exceeds {cap} bytes: {url}")
    if b"\x00" in data:
        raise ValidationError(f"NUL byte found: {url}")
    return data


def normalize_domain_token(value: str) -> str | None:
    d = value.strip().lower().rstrip(".")
    for prefix in ("+.", "*.", "."):
        if d.startswith(prefix):
            d = d[len(prefix):]
            break
    if not d or "/" in d or "://" in d or any(ch.isspace() for ch in d):
        return None
    return d


def rule_domain_pattern(line: str, fmt: str) -> tuple[str, str] | None:
    if fmt == "domain_set":
        d = normalize_domain_token(line)
        return ("suffix", d) if d else None
    parts = [x.strip() for x in line.split(",")]
    if len(parts) < 2:
        return None
    typ, val = parts[0].upper(), parts[1]
    if typ == "DOMAIN":
        d = normalize_domain_token(val)
        return ("exact", d) if d else None
    if typ == "DOMAIN-SUFFIX":
        d = normalize_domain_token(val)
        return ("suffix", d) if d else None
    if typ == "DOMAIN-KEYWORD" and val:
        return ("keyword", val.lower())
    return None


def pattern_matches_domain(pattern: tuple[str, str], domain: str) -> bool:
    kind, value = pattern
    d = domain.lower().rstrip(".")
    if kind == "exact":
        return d == value
    if kind == "suffix":
        return d == value or d.endswith("." + value)
    if kind == "keyword":
        return value in d
    return False


def validate_domain_set(lines: list[str], max_line_length: int) -> list[str]:
    errors = []
    for n, line in enumerate(lines, 1):
        if len(line) > max_line_length:
            errors.append(f"line {n}: too long")
            continue
        if "," in line or any(ch.isspace() for ch in line) or "://" in line:
            errors.append(f"line {n}: invalid DOMAIN-SET token: {line[:120]}")
            continue
        if normalize_domain_token(line) is None:
            errors.append(f"line {n}: invalid domain token: {line[:120]}")
    return errors


def validate_rule_set(lines: list[str], max_line_length: int, require_no_resolve: bool) -> list[str]:
    errors = []
    for n, line in enumerate(lines, 1):
        if len(line) > max_line_length:
            errors.append(f"line {n}: too long")
            continue
        parts = [x.strip() for x in line.split(",")]
        if len(parts) < 2:
            errors.append(f"line {n}: malformed rule: {line[:120]}")
            continue
        typ = parts[0].upper()
        if typ not in ALLOWED_RULE_TYPES:
            errors.append(f"line {n}: unreviewed rule type {typ}")
            continue
        tokens_upper = {x.upper() for x in parts[2:]}
        if tokens_upper & FORBIDDEN_POLICY_TOKENS:
            errors.append(f"line {n}: embedded routing policy is forbidden")
        if typ in {"IP-CIDR", "IP-CIDR6", "IP6-CIDR"}:
            try:
                ipaddress.ip_network(parts[1], strict=False)
            except ValueError:
                errors.append(f"line {n}: invalid CIDR {parts[1]}")
            if require_no_resolve and "NO-RESOLVE" not in tokens_upper:
                errors.append(f"line {n}: {typ} missing no-resolve")
    return errors


def duplicate_pct(lines: list[str]) -> float:
    if not lines:
        return 0.0
    return 100.0 * (len(lines) - len(set(lines))) / len(lines)


def count_change_guard(name: str, current: int, previous: int, guard: dict) -> str | None:
    if previous < int(guard["min_previous_rules"]) or previous <= 0:
        return None
    delta_pct = 100.0 * (current - previous) / previous
    if delta_pct < -float(guard["max_drop_pct"]):
        return f"{name}: rule count dropped {abs(delta_pct):.1f}% ({previous} -> {current})"
    if delta_pct > float(guard["max_growth_pct"]):
        return f"{name}: rule count grew {delta_pct:.1f}% ({previous} -> {current})"
    return None


def load_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def conflict_keys(policy_patterns: dict[str, list[tuple[str, str]]]) -> set[str]:
    direct = {f"{k}:{v}" for k, v in policy_patterns.get("DIRECT", [])}
    proxy = {f"{k}:{v}" for k, v in policy_patterns.get("PROXY", [])}
    return direct & proxy


def build_report(result: dict) -> str:
    ok = result["status"] == "PASS"
    lines = [
        f"# Shadowrocket Safe Rules — {'PASS' if ok else 'FAIL'}",
        "",
        f"- Time (UTC): `{result['generated_at']}`",
        f"- Sources checked: **{result.get('source_count', 0)}**",
        f"- Total active rules: **{result.get('total_rules', 0):,}**",
        f"- New DIRECT/PROXY exact conflicts: **{len(result.get('new_conflicts', []))}**",
        f"- Existing exact conflicts: **{len(result.get('all_conflicts', []))}**",
        "",
    ]
    if result.get("errors"):
        lines += ["## Blocking errors", ""]
        lines += [f"- {x}" for x in result["errors"]]
        lines.append("")
    if result.get("warnings"):
        lines += ["## Warnings", ""]
        lines += [f"- {x}" for x in result["warnings"]]
        lines.append("")
    if result.get("sources"):
        lines += ["## Sources", "", "| Source | Policy | Rules | SHA-256 |", "|---|---:|---:|---|"]
        for s in result["sources"]:
            lines.append(f"| {s['name']} | {s['policy']} | {s['count']:,} | `{s['sha256'][:16]}…` |")
        lines.append("")
    lines += [
        "## Fail-closed behavior",
        "",
        "If this run fails, `rules/` and `state/manifest.json` are not published by the validator.",
        "The phone therefore continues using the last approved mirror.",
        "",
    ]
    return "\n".join(lines)


def run(config_path: Path, repo_root: Path, report_path: Path) -> int:
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    if cfg.get("version") != 1:
        raise ValidationError("unsupported config version")

    state_path = repo_root / "state" / "manifest.json"
    previous = load_json(state_path, {})
    previous_sources = previous.get("sources", {})
    baseline_conflicts = set(previous.get("conflicts", []))

    result = {
        "status": "FAIL",
        "generated_at": utc_now(),
        "source_count": len(cfg["sources"]),
        "total_rules": 0,
        "sources": [],
        "errors": [],
        "warnings": [],
        "all_conflicts": [],
        "new_conflicts": [],
    }

    staging_dir = Path(tempfile.mkdtemp(prefix="sr-safe-rules-"))
    policy_patterns: dict[str, list[tuple[str, str]]] = defaultdict(list)
    try:
        outputs_seen = set()
        names_seen = set()

        for src in cfg["sources"]:
            name = src["name"]
            if name in names_seen:
                result["errors"].append(f"duplicate source name: {name}")
                continue
            names_seen.add(name)

            output = safe_relpath(src["output"])
            if output in outputs_seen:
                result["errors"].append(f"duplicate output path: {output}")
                continue
            outputs_seen.add(output)

            policy = src["policy"].upper()
            fmt = src["format"]
            if policy not in {"DIRECT", "PROXY"}:
                result["errors"].append(f"{name}: unsupported policy {policy}")
                continue
            if fmt not in {"rule_set", "domain_set"}:
                result["errors"].append(f"{name}: unsupported format {fmt}")
                continue

            try:
                data = download(src["url"], cfg)
                text = data.decode("utf-8-sig")
            except Exception as exc:
                result["errors"].append(f"{name}: download/decode failed: {exc}")
                continue

            lines = active_lines(text)
            count = len(lines)
            if count < int(src["min_rules"]):
                result["errors"].append(
                    f"{name}: too few rules ({count} < minimum {src['min_rules']})"
                )

            max_len = int(cfg["global"]["max_line_length"])
            if fmt == "rule_set":
                errs = validate_rule_set(
                    lines, max_len, bool(cfg["global"].get("require_no_resolve_for_ip", True))
                )
            else:
                errs = validate_domain_set(lines, max_len)
            result["errors"].extend(f"{name}: {e}" for e in errs[:25])
            if len(errs) > 25:
                result["errors"].append(f"{name}: {len(errs)-25} additional syntax errors omitted")

            dup = duplicate_pct(lines)
            if dup > float(cfg["global"]["max_duplicate_pct"]):
                result["errors"].append(
                    f"{name}: duplicate ratio {dup:.2f}% exceeds {cfg['global']['max_duplicate_pct']}%"
                )
            elif dup > 0:
                result["warnings"].append(f"{name}: duplicate ratio {dup:.2f}%")

            prev_count = previous_sources.get(name, {}).get("count")
            if isinstance(prev_count, int):
                anomaly = count_change_guard(
                    name, count, prev_count, cfg["global"]["change_guard"]
                )
                if anomaly:
                    result["errors"].append(anomaly)

            normalized = "\n".join(lines) + ("\n" if lines else "")
            staged = staging_dir / output
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_text(normalized, encoding="utf-8")

            digest = sha256_bytes(normalized.encode("utf-8"))
            meta = {
                "name": name,
                "policy": policy,
                "format": fmt,
                "count": count,
                "sha256": digest,
                "url": src["url"],
                "output": output,
            }
            result["sources"].append(meta)
            result["total_rules"] += count

            for line in lines:
                pat = rule_domain_pattern(line, fmt)
                if pat:
                    policy_patterns[policy].append(pat)

        current_conflicts = conflict_keys(policy_patterns)
        new_conflicts = current_conflicts - baseline_conflicts if previous else set()
        result["all_conflicts"] = sorted(current_conflicts)
        result["new_conflicts"] = sorted(new_conflicts)
        if previous and new_conflicts:
            sample = ", ".join(sorted(new_conflicts)[:20])
            result["errors"].append(
                f"new DIRECT/PROXY exact conflicts introduced: {len(new_conflicts)}; sample: {sample}"
            )
        elif not previous and current_conflicts:
            result["warnings"].append(
                f"bootstrap recorded {len(current_conflicts)} existing exact conflicts as baseline"
            )

        for domain in cfg.get("protected_proxy_domains", []):
            matches = [p for p in policy_patterns.get("DIRECT", []) if pattern_matches_domain(p, domain)]
            if matches:
                result["errors"].append(
                    f"protected PROXY domain appears in DIRECT upstream patterns: {domain} -> {matches[:5]}"
                )

        if result["errors"]:
            result["status"] = "FAIL"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(build_report(result), encoding="utf-8")
            return 1

        for src in cfg["sources"]:
            output = safe_relpath(src["output"])
            staged = staging_dir / output
            dest = repo_root / output
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(staged, dest)

        manifest = {
            "version": 1,
            "approved_at": result["generated_at"],
            "sources": {m["name"]: m for m in result["sources"]},
            "conflicts": sorted(current_conflicts),
            "total_rules": result["total_rules"],
        }
        write_json(state_path, manifest)

        result["status"] = "PASS"
        reports = repo_root / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        write_json(reports / "latest.json", result)
        (reports / "latest.md").write_text(build_report(result), encoding="utf-8")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(build_report(result), encoding="utf-8")
        return 0
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="sources.json")
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--report", default="/tmp/validation-report.md")
    args = ap.parse_args()
    try:
        return run(Path(args.config), Path(args.repo_root), Path(args.report))
    except ValidationError as exc:
        print(f"VALIDATION ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"UNEXPECTED ERROR: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
