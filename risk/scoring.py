"""Risk scoring utilities using EPSS, KEV, and SBOM metadata."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Sequence

from packaging.version import InvalidVersion, Version
from telemetry import get_meter, get_tracer

EXPOSURE_ALIASES = {
    "internet": "internet",
    "internet_exposed": "internet",
    "internet-facing": "internet",
    "internet_facing": "internet",
    "public": "public",
    "external": "public",
    "dmz": "public",
    "partner": "partner",
    "saas": "partner",
    "multi-tenant": "partner",
    "tenant": "partner",
    "internal": "internal",
    "intranet": "internal",
    "onprem": "internal",
    "controlled": "controlled",
    "limited": "controlled",
    "restricted": "controlled",
    "unknown": "unknown",
    "": "unknown",
}

EXPOSURE_WEIGHTS = {
    "internet": 1.0,
    "public": 0.9,
    "partner": 0.7,
    "internal": 0.5,
    "controlled": 0.4,
    "unknown": 0.3,
}

DEFAULT_WEIGHTS = {
    "epss": 0.5,
    "kev": 0.2,
    "version_lag": 0.2,
    "exposure": 0.1,
}

VERSION_LAG_CAP_DAYS = 180.0


_TRACER = get_tracer("fixops.risk")
_METER = get_meter("fixops.risk")
_RISK_COUNTER = _METER.create_counter(
    "fixops_risk_profiles",
    description="Number of risk profiles computed",
)

def _component_key(component: Mapping[str, Any]) -> str:
    purl = component.get("purl")
    if isinstance(purl, str) and purl:
        return purl
    name = component.get("name") or "unknown"
    version = component.get("version") or "unspecified"
    return f"{name}@{version}"


def _slugify(value: str) -> str:
    slug = value.replace("@", "-")
    for char in ("/", ":", "|", " "):
        slug = slug.replace(char, "-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-").lower() or "component"


def _collect_strings(candidate: Any) -> Iterable[str]:
    if isinstance(candidate, str):
        yield candidate
    elif isinstance(candidate, Mapping):
        for value in candidate.values():
            yield from _collect_strings(value)
    elif isinstance(candidate, Sequence) and not isinstance(candidate, (bytes, bytearray)):
        for item in candidate:
            yield from _collect_strings(item)


def _normalize_exposure(flag: str) -> str:
    key = flag.strip().lower().replace(" ", "_").replace("-", "_")
    return EXPOSURE_ALIASES.get(key, key or "unknown")


def _collect_exposure_flags(*sources: Any) -> list[str]:
    flags = {"unknown"}
    for source in sources:
        for raw in _collect_strings(source):
            normalized = _normalize_exposure(raw)
            if normalized:
                flags.add(normalized)
    if "unknown" in flags and len(flags) > 1:
        flags.remove("unknown")
    return sorted(flags)


def _exposure_factor(flags: Sequence[str]) -> float:
    if not flags:
        return EXPOSURE_WEIGHTS["unknown"]
    weight = max(EXPOSURE_WEIGHTS.get(flag, EXPOSURE_WEIGHTS["unknown"]) for flag in flags)
    return weight


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _coerce_float(value: Any, *, default: float = 0.0) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _estimate_lag_from_versions(current: str, target: str) -> float:
    try:
        current_version = Version(current)
        target_version = Version(target)
    except InvalidVersion:
        return 0.0
    if target_version <= current_version:
        return 0.0
    current_release = list(current_version.release) + [0] * (3 - len(current_version.release))
    target_release = list(target_version.release) + [0] * (3 - len(target_version.release))
    major_delta = max(target_release[0] - current_release[0], 0)
    minor_delta = max(target_release[1] - current_release[1], 0)
    patch_delta = max(target_release[2] - current_release[2], 0)
    return major_delta * 365 + minor_delta * 90 + patch_delta * 30


def _infer_version_lag_days(component: Mapping[str, Any], vulnerability: Mapping[str, Any]) -> float:
    for key in ("version_lag_days", "lag_days", "age_days"):
        if key in vulnerability:
            return max(0.0, _coerce_float(vulnerability[key]))
    for key in ("version_lag_days", "lag_days", "age_days"):
        if key in component:
            return max(0.0, _coerce_float(component[key]))

    fix_version = vulnerability.get("fix_version") or vulnerability.get("patched_version")
    current_version = component.get("version")
    if isinstance(fix_version, str) and isinstance(current_version, str):
        lag = _estimate_lag_from_versions(current_version, fix_version)
        if lag > 0:
            return lag

    fix_date = _parse_datetime(vulnerability.get("fixed_release_date"))
    last_seen = _parse_datetime(component.get("last_observed") or component.get("last_seen"))
    if fix_date and last_seen and fix_date > last_seen:
        return float((fix_date - last_seen).days)

    return 0.0


def _lag_factor(days: float) -> float:
    if days <= 0:
        return 0.0
    return min(days / VERSION_LAG_CAP_DAYS, 1.0)


def _score_vulnerability(
    component: Mapping[str, Any],
    vulnerability: Mapping[str, Any],
    epss_scores: Mapping[str, float],
    kev_entries: Mapping[str, Any],
    weights: Mapping[str, float],
) -> Dict[str, Any] | None:
    cve = vulnerability.get("cve") or vulnerability.get("cve_id") or vulnerability.get("id")
    if not isinstance(cve, str) or not cve:
        return None
    cve_id = cve.upper()

    epss = float(epss_scores.get(cve_id, 0.0))
    kev_present = cve_id in kev_entries
    lag_days = _infer_version_lag_days(component, vulnerability)
    lag_score = _lag_factor(lag_days)
    exposure_flags = _collect_exposure_flags(
        component.get("exposure"),
        component.get("exposure_flags"),
        component.get("tags"),
        vulnerability.get("exposure"),
        vulnerability.get("exposure_flags"),
        vulnerability.get("tags"),
    )
    exposure_score = _exposure_factor(exposure_flags)

    contributions = {
        "epss": epss,
        "kev": 1.0 if kev_present else 0.0,
        "version_lag": lag_score,
        "exposure": exposure_score,
    }

    total_weight = sum(weights.values())
    weighted_score = sum(contributions[key] * weights[key] for key in contributions)
    normalized_score = weighted_score / total_weight if total_weight else 0.0
    final_score = round(normalized_score * 100, 2)

    return {
        "cve": cve_id,
        "epss": round(epss, 4),
        "kev": kev_present,
        "version_lag_days": round(lag_days, 2),
        "exposure_flags": exposure_flags,
        "risk_breakdown": {
            "weights": dict(weights),
            "contributions": contributions,
            "normalized_score": round(normalized_score, 4),
        },
        "fixops_risk": final_score,
    }


def compute_risk_profile(
    normalized_sbom: Mapping[str, Any],
    epss_scores: Mapping[str, float],
    kev_entries: Mapping[str, Any],
    *,
    weights: Mapping[str, float] = DEFAULT_WEIGHTS,
) -> Dict[str, Any]:
    """Compute a composite risk profile for the provided SBOM."""

    with _TRACER.start_as_current_span("risk.compute_profile") as span:
        components = []
        cve_index: MutableMapping[str, Dict[str, Any]] = {}

        for component in normalized_sbom.get("components", []):
            if not isinstance(component, Mapping):
                continue
            vulnerabilities = component.get("vulnerabilities")
            if not isinstance(vulnerabilities, Sequence):
                continue
            key = _component_key(component)
            slug = component.get("slug") or _slugify(key)
            component_entry = {
                "id": key,
                "slug": slug,
                "name": component.get("name"),
                "version": component.get("version"),
                "purl": component.get("purl"),
                "vulnerabilities": [],
                "exposure_flags": _collect_exposure_flags(
                    component.get("exposure"),
                    component.get("exposure_flags"),
                    component.get("tags"),
                ),
            }
            max_score = 0.0
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, Mapping):
                    continue
                scored = _score_vulnerability(component, vulnerability, epss_scores, kev_entries, weights)
                if not scored:
                    continue
                component_entry["vulnerabilities"].append(scored)
                max_score = max(max_score, scored["fixops_risk"])
                cve_info = cve_index.setdefault(
                    scored["cve"],
                    {"cve": scored["cve"], "max_risk": 0.0, "components": []},
                )
                cve_info["max_risk"] = max(cve_info["max_risk"], scored["fixops_risk"])
                if slug not in cve_info["components"]:
                    cve_info["components"].append(slug)
            if component_entry["vulnerabilities"]:
                component_entry["component_risk"] = round(max_score, 2)
                components.append(component_entry)

        highest_component = max(
            components,
            key=lambda item: item.get("component_risk", 0.0),
            default=None,
        )

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "weights": dict(weights),
            "components": sorted(components, key=lambda item: item["id"]),
            "cves": {
                cve: {
                    "cve": details["cve"],
                    "max_risk": round(details["max_risk"], 2),
                    "components": sorted(details["components"]),
                }
                for cve, details in cve_index.items()
            },
        }
        report["summary"] = {
            "component_count": len(report["components"]),
            "cve_count": len(report["cves"]),
            "highest_risk_component": highest_component["slug"] if highest_component else None,
            "max_risk_score": highest_component.get("component_risk", 0.0) if highest_component else 0.0,
        }
        span.set_attribute("fixops.risk.components", report["summary"]["component_count"])
        span.set_attribute("fixops.risk.cves", report["summary"]["cve_count"])
        _RISK_COUNTER.add(1, {"status": "computed"})
        return report


def write_risk_report(
    normalized_sbom_path: str | Path,
    destination: str | Path,
    epss_scores: Mapping[str, float],
    kev_entries: Mapping[str, Any],
    *,
    weights: Mapping[str, float] = DEFAULT_WEIGHTS,
) -> Dict[str, Any]:
    """Load the normalized SBOM and write a computed risk profile to ``destination``."""

    sbom_path = Path(normalized_sbom_path)
    with sbom_path.open("r", encoding="utf-8") as handle:
        normalized = json.load(handle)

    report = compute_risk_profile(normalized, epss_scores, kev_entries, weights=weights)
    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    with destination_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return report


__all__ = [
    "compute_risk_profile",
    "write_risk_report",
    "DEFAULT_WEIGHTS",
    "VERSION_LAG_CAP_DAYS",
]
