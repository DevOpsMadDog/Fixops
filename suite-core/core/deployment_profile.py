"""One switch that selects a coherent deployment posture.

FixOps is sold into two very different places: ordinary commercial estates, and
accredited air-gapped environments where a single outbound packet is an incident. Those
differ in exactly two respects — where AI inference happens, and whether egress is
permitted — and in nothing else. Ingest, deduplication, enrichment, risk scoring, triage
and evidence generation make no assumption about network reachability.

Treating them as two products is what produced much of the current breadth. Treating
them as two *profiles* keeps one codebase and one test matrix::

                    commercial              scif
    council         cloud providers         local inference only
    egress          unrestricted            enforced
    crypto          default                 FIPS required
    threat feeds    live fetch              signed offline bundle
    everything else identical                identical

The profile is **fail-closed**. Selecting ``scif`` while a cloud LLM key is configured is
a startup error, not a warning. In an accreditation boundary, a log line is not an
adequate guard against an outbound call — the process must refuse to run.

See docs/architecture/adr/001-single-product-two-deployment-profiles.md.
"""

from __future__ import annotations

import logging
import os
from enum import Enum
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

__all__ = [
    "DeploymentProfile",
    "ProfileViolation",
    "get_profile",
    "cloud_llm_keys_present",
    "profile_posture",
    "validate_profile",
    "apply_profile_defaults",
]

ENV_VAR = "FIXOPS_PROFILE"

# Environment variables that, if set, mean an outbound LLM call is possible.
CLOUD_LLM_KEY_VARS: Tuple[str, ...] = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "OPENROUTER_API_KEY",
    "MULEROUTER_API_KEY",
    "DEEPSEEK_API_KEY",
)


class DeploymentProfile(str, Enum):
    COMMERCIAL = "commercial"
    SCIF = "scif"


class ProfileViolation(RuntimeError):
    """The declared profile conflicts with the actual configuration.

    Raised at startup so a misconfigured accredited deployment cannot begin serving.
    """


def get_profile() -> DeploymentProfile:
    """Return the declared profile, defaulting to commercial.

    An unrecognised value is a configuration error rather than something to guess at:
    silently falling back to ``commercial`` for a typo like ``FIXOPS_PROFILE=SCIFF``
    would drop every air-gap protection at the moment they are most needed.
    """
    raw = os.getenv(ENV_VAR, "").strip().lower()
    if not raw:
        return DeploymentProfile.COMMERCIAL
    try:
        return DeploymentProfile(raw)
    except ValueError as exc:
        valid = ", ".join(p.value for p in DeploymentProfile)
        raise ProfileViolation(
            f"{ENV_VAR}={raw!r} is not a known profile (expected one of: {valid}). "
            "Refusing to start rather than guess — an unrecognised profile would "
            "silently drop the air-gap protections."
        ) from exc


def cloud_llm_keys_present() -> List[str]:
    """Names of cloud LLM credentials currently visible in the environment."""
    return [name for name in CLOUD_LLM_KEY_VARS if os.getenv(name, "").strip()]


def profile_posture(profile: DeploymentProfile) -> Dict[str, str]:
    """The settings this profile implies, for logging and for /api/v1/app-config."""
    if profile is DeploymentProfile.SCIF:
        return {
            "council": "local inference only",
            "egress": "enforced",
            "crypto": "FIPS required",
            "threat_feeds": "signed offline bundle",
        }
    return {
        "council": "cloud providers",
        "egress": "unrestricted",
        "crypto": "default",
        "threat_feeds": "live fetch",
    }


def validate_profile(profile: DeploymentProfile | None = None) -> None:
    """Raise :class:`ProfileViolation` if the configuration contradicts the profile.

    Only ``scif`` has anything to violate: ``commercial`` permits everything ``scif``
    permits and more.
    """
    profile = profile or get_profile()
    if profile is not DeploymentProfile.SCIF:
        return

    problems: List[str] = []

    keys = cloud_llm_keys_present()
    if keys:
        problems.append(
            f"cloud LLM credentials are configured ({', '.join(keys)}). Under the scif "
            "profile the council must run entirely on local inference; a configured key "
            "means an outbound call is reachable."
        )

    airgap = os.getenv("FIXOPS_AIRGAP_MODE", "").strip().lower()
    if airgap != "enforced":
        problems.append(
            f"FIXOPS_AIRGAP_MODE is {airgap or 'unset'!r}, not 'enforced'. Without it the "
            "socket-level egress guard is inactive and outbound access is unrestricted."
        )

    if problems:
        raise ProfileViolation(
            "scif profile refused to start:\n  - " + "\n  - ".join(problems)
        )


def apply_profile_defaults() -> DeploymentProfile:
    """Set the environment implied by the profile, then validate it.

    Defaults are only *filled in*; anything explicitly configured is left alone, so an
    operator can always be more restrictive than the profile requires but never less.
    """
    profile = get_profile()
    if profile is DeploymentProfile.SCIF:
        os.environ.setdefault("FIXOPS_AIRGAP_MODE", "enforced")
        os.environ.setdefault("FIPS_MODE", "enforced")
        os.environ.setdefault("FIPS_MODE_REQUIRED", "1")

    validate_profile(profile)

    posture = profile_posture(profile)
    logger.info(
        "deployment profile: %s (%s)",
        profile.value,
        ", ".join(f"{k}={v}" for k, v in posture.items()),
    )
    return profile
