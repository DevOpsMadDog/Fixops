"""SBOM normalization and quality scoring utilities."""

from __future__ import annotations

import json
import logging
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
)

PREFERRED_HASH_ORDER = (
    "SHA512",
    "SHA384",
    "SHA256",
    "SHA224",
    "SHA1",
    "MD5",
)


@dataclass
class NormalizedComponent:
    """Container for merged component metadata."""

    name: Optional[str]
    version: Optional[str]
    purl: Optional[str]
    hashes: MutableMapping[str, str] = field(default_factory=dict)
    licenses: set[str] = field(default_factory=set)
    generators: set[str] = field(default_factory=set)

    def to_json(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "hashes": {key: self.hashes[key] for key in sorted(self.hashes)},
            "licenses": sorted(self.licenses),
            "generators": sorted(self.generators),
        }


def _load_document(path: Path) -> Mapping[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, Mapping):
        raise ValueError(f"Unsupported SBOM structure in {path}")
    return data


def _detect_format(document: Mapping[str, Any]) -> str:
    if isinstance(document.get("bomFormat"), str):
        return document["bomFormat"].lower()
    if "spdxVersion" in document:
        return "spdx"
    if document.get("metadata", {}).get("tools"):
        return "cyclonedx"
    return "unknown"


def _extract_generators(document: Mapping[str, Any], *, fallback: str) -> List[str]:
    generators: List[str] = []
    metadata = document.get("metadata")
    if isinstance(metadata, Mapping):
        tools = metadata.get("tools")
        if isinstance(tools, Mapping):
            components = tools.get("components")
            if isinstance(components, Sequence):
                for component in components:
                    if isinstance(component, Mapping):
                        name = component.get("name")
                        vendor = component.get("vendor")
                        version = component.get("version")
                        parts = [
                            str(part)
                            for part in (vendor, name, version)
                            if isinstance(part, str) and part
                        ]
                        if parts:
                            generators.append(" ".join(parts))
        elif isinstance(tools, Sequence):
            for tool in tools:
                if isinstance(tool, Mapping):
                    name = tool.get("name")
                    version = tool.get("version")
                    if isinstance(name, str):
                        generators.append(
                            f"{name} {version}" if isinstance(version, str) else name
                        )
    creation = document.get("creationInfo")
    if isinstance(creation, Mapping):
        creators = creation.get("creators")
        if isinstance(creators, Sequence):
            for creator in creators:
                if isinstance(creator, str) and creator:
                    generators.append(creator)
    if not generators:
        generators.append(fallback)
    return sorted({gen.strip(): None for gen in generators if gen}.keys())


def _extract_hashes(candidate: Mapping[str, Any]) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    hash_entries = candidate.get("hashes")
    if isinstance(hash_entries, Sequence):
        for entry in hash_entries:
            if isinstance(entry, Mapping):
                algorithm = entry.get("alg") or entry.get("algorithm")
                value = (
                    entry.get("content")
                    or entry.get("value")
                    or entry.get("checksumValue")
                )
                if isinstance(algorithm, str) and isinstance(value, str):
                    hashes[algorithm.upper()] = value
    checksum_entries = candidate.get("checksums")
    if isinstance(checksum_entries, Sequence):
        for checksum in checksum_entries:
            if isinstance(checksum, Mapping):
                algorithm = checksum.get("algorithm")
                value = checksum.get("checksumValue")
                if isinstance(algorithm, str) and isinstance(value, str):
                    hashes[algorithm.upper()] = value
    return hashes


def _extract_licenses(candidate: Mapping[str, Any]) -> List[str]:
    licenses: List[str] = []
    if isinstance(candidate.get("licenses"), Sequence):
        for item in candidate["licenses"]:
            if isinstance(item, Mapping):
                license_obj = item.get("license")
                if isinstance(license_obj, Mapping):
                    name = license_obj.get("name")
                    if isinstance(name, str):
                        licenses.append(name)
                expression = item.get("expression")
                if isinstance(expression, str):
                    licenses.append(expression)
    for key in ("licenseConcluded", "licenseDeclared"):
        value = candidate.get(key)
        if isinstance(value, str) and value and value != "NOASSERTION":
            licenses.append(value)
    seen: Dict[str, None] = {}
    for entry in licenses:
        entry = entry.strip()
        if entry:
            seen.setdefault(entry, None)
    return list(seen.keys())


def _extract_purl(candidate: Mapping[str, Any]) -> Optional[str]:
    purl = candidate.get("purl")
    if isinstance(purl, str) and purl:
        return purl
    external_refs = candidate.get("externalRefs")
    if isinstance(external_refs, Sequence):
        for ref in external_refs:
            if isinstance(ref, Mapping):
                ref_type = ref.get("referenceType")
                locator = ref.get("referenceLocator")
                if ref_type == "purl" and isinstance(locator, str):
                    return locator
    return None


def _component_from_cyclonedx(
    candidate: Mapping[str, Any]
) -> Tuple[str, Optional[str], Optional[str], Dict[str, str], List[str]]:
    name = candidate.get("name") if isinstance(candidate.get("name"), str) else None
    version = (
        candidate.get("version") if isinstance(candidate.get("version"), str) else None
    )
    purl = _extract_purl(candidate)
    hashes = _extract_hashes(candidate)
    licenses = _extract_licenses(candidate)
    return name, version, purl, hashes, licenses


def _component_from_spdx(
    candidate: Mapping[str, Any]
) -> Tuple[str, Optional[str], Optional[str], Dict[str, str], List[str]]:
    name = candidate.get("name") if isinstance(candidate.get("name"), str) else None
    version = candidate.get("versionInfo")
    if not isinstance(version, str):
        version = (
            candidate.get("version")
            if isinstance(candidate.get("version"), str)
            else None
        )
    purl = _extract_purl(candidate)
    hashes = _extract_hashes(candidate)
    licenses = _extract_licenses(candidate)
    return name, version, purl, hashes, licenses


def _normalise_candidates(
    document: Mapping[str, Any]
) -> List[Tuple[str, Optional[str], Optional[str], Dict[str, str], List[str]]]:
    format_hint = _detect_format(document)
    candidates: Sequence[Any]
    if format_hint.startswith("cyclonedx") or "components" in document:
        raw_components = document.get("components")
        if isinstance(raw_components, Sequence):
            return [
                _component_from_cyclonedx(component)
                for component in raw_components
                if isinstance(component, Mapping)
            ]
    packages = document.get("packages")
    if isinstance(packages, Sequence):
        return [
            _component_from_spdx(package)
            for package in packages
            if isinstance(package, Mapping)
        ]
    return []


def _prefer_value(existing: Optional[str], candidate: Optional[str]) -> Optional[str]:
    if existing:
        return existing
    return candidate or existing


def _identity_for(
    purl: Optional[str], version: Optional[str], hashes: Mapping[str, str]
) -> Tuple[str, str, str]:
    preferred_hash = ""
    if hashes:
        for algorithm in PREFERRED_HASH_ORDER:
            if algorithm in hashes:
                preferred_hash = f"{algorithm}:{hashes[algorithm]}"
                break
        else:
            sorted_hashes = sorted(hashes.items())
            if sorted_hashes:
                algorithm, value = sorted_hashes[0]
                preferred_hash = f"{algorithm}:{value}"
    if purl and version:
        return (purl, version, "")
    if purl:
        return (purl, "", preferred_hash)
    if preferred_hash:
        return ("", "", preferred_hash)
    return ("", version or "", "")


def normalize_sboms(paths: Iterable[str | Path]) -> Dict[str, Any]:
    aggregated: Dict[Tuple[str, str, str], NormalizedComponent] = {}
    generator_components: Dict[str, set[Tuple[str, str, str]]] = defaultdict(set)
    total_components = 0
    sources: List[Dict[str, Any]] = []
    validation_errors: List[Dict[str, Any]] = []

    for raw_path in paths:
        path = Path(raw_path)
        document = _load_document(path)
        format_hint = _detect_format(document)
        generators = _extract_generators(document, fallback=path.stem)
        components = _normalise_candidates(document)
        total_components += len(components)
        for generator in generators:
            sources.append(
                {
                    "path": str(path),
                    "format": format_hint,
                    "generator": generator,
                    "component_count": len(components),
                }
            )
        if not generators:
            sources.append(
                {
                    "path": str(path),
                    "format": format_hint,
                    "generator": path.stem,
                    "component_count": len(components),
                }
            )
            generators = [path.stem]
        for name, version, purl, hashes, licenses in components:
            normalized_name = name.lower().strip() if isinstance(name, str) else None
            normalized_version = version.strip() if isinstance(version, str) else None
            normalized_purl = purl.lower().strip() if isinstance(purl, str) else None

            missing_fields = [
                field
                for field, value in (
                    ("name", normalized_name),
                    ("version", normalized_version),
                    ("purl", normalized_purl),
                )
                if not value
            ]
            if missing_fields:
                validation_errors.append(
                    {
                        "path": str(path),
                        "generator": generators,
                        "missing_fields": missing_fields,
                    }
                )
                LOGGER.warning(
                    "Component missing required fields %s in %s", missing_fields, path
                )

            identity = _identity_for(normalized_purl, normalized_version, hashes)
            component = aggregated.get(identity)
            if component is None:
                component = NormalizedComponent(
                    name=normalized_name,
                    version=normalized_version,
                    purl=normalized_purl,
                )
                aggregated[identity] = component
            component.name = _prefer_value(component.name, normalized_name)
            component.version = _prefer_value(component.version, normalized_version)
            component.purl = _prefer_value(component.purl, normalized_purl)
            component.hashes.update({k.upper(): v for k, v in hashes.items()})
            component.licenses.update(licenses)
            component.generators.update(generators)
            for generator in generators:
                generator_components[generator].add(identity)

    normalized_components = [comp.to_json() for comp in aggregated.values()]
    normalized_components.sort(
        key=lambda entry: (
            entry.get("purl") or "",
            entry.get("name") or "",
            entry.get("version") or "",
        )
    )

    metadata = {
        "generated_at": _now().isoformat(),
        "total_components": total_components,
        "unique_components": len(aggregated),
        "generator_count": len(generator_components),
        "component_keys_by_generator": {
            generator: ["|".join(identity) for identity in sorted(identities)]
            for generator, identities in generator_components.items()
        },
        "validation_errors": validation_errors,
    }

    return {
        "metadata": metadata,
        "components": normalized_components,
        "sources": sources,
    }


def write_normalized_sbom(
    paths: Iterable[str | Path], destination: str | Path
) -> Dict[str, Any]:
    normalized = normalize_sboms(paths)
    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    with destination_path.open("w", encoding="utf-8") as handle:
        json.dump(normalized, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return normalized


def _safe_percentage(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round((numerator / denominator) * 100, 2)


def build_quality_report(normalized: Mapping[str, Any]) -> Dict[str, Any]:
    metadata = normalized.get("metadata", {})
    total_components = metadata.get("total_components")
    unique_components = metadata.get("unique_components")
    if not isinstance(total_components, int):
        total_components = len(normalized.get("components", []))
    if not isinstance(unique_components, int):
        unique_components = len(normalized.get("components", []))

    components = normalized.get("components", [])
    license_count = 0
    resolvable_count = 0
    for component in components:
        licenses = component.get("licenses", [])
        if isinstance(licenses, Sequence) and any(
            isinstance(item, str) and item for item in licenses
        ):
            license_count += 1
        if component.get("purl") or component.get("hashes"):
            resolvable_count += 1

    coverage = _safe_percentage(
        unique_components, total_components or unique_components
    )
    license_coverage = _safe_percentage(license_count, unique_components)
    resolvability = _safe_percentage(resolvable_count, unique_components)

    generator_sets = metadata.get("component_keys_by_generator", {})
    union: set[str] = set()
    intersection: Optional[set[str]] = None
    for identity_list in generator_sets.values():
        identity_set = {str(item) for item in identity_list}
        union.update(identity_set)
        if intersection is None:
            intersection = set(identity_set)
        else:
            intersection.intersection_update(identity_set)
    if not generator_sets:
        variance = 0.0
    elif not union:
        variance = 0.0
    elif intersection is None:
        variance = 0.0
    else:
        variance = round(1.0 - (len(intersection) / len(union)), 4)

    policy_status = "pass"
    warnings: List[str] = []
    if coverage < 80:
        policy_status = "warn"
        warnings.append("Component coverage below 80 percent")

    return {
        "generated_at": _now().isoformat(),
        "unique_components": unique_components,
        "total_components": total_components,
        "metrics": {
            "coverage_percent": coverage,
            "license_coverage_percent": license_coverage,
            "resolvability_percent": resolvability,
            "generator_variance_score": variance,
        },
        "policy_status": policy_status,
        "warnings": warnings,
    }


def write_quality_report(
    normalized: Mapping[str, Any],
    json_destination: str | Path,
) -> Dict[str, Any]:
    report = build_quality_report(normalized)
    path = Path(json_destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return report


def render_html_report(report: Mapping[str, Any], destination: str | Path) -> Path:
    metrics = report.get("metrics", {})
    rows = []
    for key, label in (
        ("coverage_percent", "Component Coverage"),
        ("license_coverage_percent", "License Coverage"),
        ("resolvability_percent", "Resolvable Components"),
        ("generator_variance_score", "Generator Variance"),
    ):
        value = metrics.get(key)
        if isinstance(value, (int, float)):
            display = f"{value:.2f}%" if "percent" in key else f"{value:.4f}"
            gauge = (
                f"<div class='gauge'><div class='bar' style='width: {min(max(value, 0.0), 100.0)}%'></div></div>"
                if "percent" in key
                else ""
            )
        else:
            display = "N/A"
            gauge = ""
        rows.append(f"<tr><th>{label}</th><td>{display}</td><td>{gauge}</td></tr>")

    html = f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\" />
<title>FixOps SBOM Quality Report</title>
<style>
body {{ font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 2rem; color: #1f2933; }}
h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
p.meta {{ color: #52606d; margin-top: 0; }}
table {{ border-collapse: collapse; width: 100%; max-width: 720px; margin-top: 1.5rem; }}
th, td {{ border: 1px solid #d9e2ec; padding: 0.5rem 0.75rem; text-align: left; }}
th {{ background-color: #f0f4f8; width: 30%; }}
.gauge {{ background: #d9e2ec; border-radius: 999px; height: 0.5rem; width: 100%; overflow: hidden; }}
.gauge .bar {{ background: #2bb0ed; height: 100%; }}
small {{ color: #829ab1; }}
</style>
</head>
<body>
<h1>SBOM Quality Report</h1>
<p class=\"meta\">Generated at: {report.get('generated_at', 'unknown')}</p>
<p class=\"meta\">Unique components: {report.get('unique_components', 'N/A')} &mdash; Total observations: {report.get('total_components', 'N/A')}</p>
<table>
<thead><tr><th>Metric</th><th>Value</th><th>Visual</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body>
</html>
"""
    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    destination_path.write_text(html, encoding="utf-8")
    return destination_path


def build_and_write_quality_outputs(
    normalized: Mapping[str, Any],
    json_destination: str | Path,
    html_destination: str | Path,
) -> Dict[str, Any]:
    report = write_quality_report(normalized, json_destination)
    render_html_report(report, html_destination)
    return report


LOGGER = logging.getLogger(__name__)


def _now() -> datetime:
    """Return a reproducible timestamp when FIXOPS_TEST_SEED is present."""

    seed = os.getenv("FIXOPS_TEST_SEED")
    if seed:
        normalized_seed = seed.replace("Z", "+00:00")
        seeded = datetime.fromisoformat(normalized_seed)
        if seeded.tzinfo is None:
            seeded = seeded.replace(tzinfo=timezone.utc)
        else:
            seeded = seeded.astimezone(timezone.utc)
        return seeded
    return datetime.now(timezone.utc)
