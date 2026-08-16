"""The scif profile must refuse to start rather than risk an outbound call.

FixOps is sold into ordinary commercial estates and into accredited air-gapped
environments. Those differ in exactly two respects — where inference happens and whether
egress is permitted — so they are one product with one switch, not two products.

What makes the switch worth anything is that it fails *closed*. Inside an accreditation
boundary a log line saying "cloud key configured, ignoring" is not a control; the process
must refuse to serve. These tests pin that behaviour, including the failure mode that
would be easiest to get wrong: a typo'd profile name silently falling back to
``commercial`` and dropping every protection at the moment it matters most.

See docs/architecture/adr/001-single-product-two-deployment-profiles.md.
"""

from __future__ import annotations

import pytest

from core.deployment_profile import (
    CLOUD_LLM_KEY_VARS,
    DeploymentProfile,
    ProfileViolation,
    apply_profile_defaults,
    cloud_llm_keys_present,
    get_profile,
    profile_posture,
    validate_profile,
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    """Start each test from a known-empty posture."""
    monkeypatch.delenv("FIXOPS_PROFILE", raising=False)
    monkeypatch.delenv("FIXOPS_AIRGAP_MODE", raising=False)
    monkeypatch.delenv("FIPS_MODE", raising=False)
    monkeypatch.delenv("FIPS_MODE_REQUIRED", raising=False)
    for name in CLOUD_LLM_KEY_VARS:
        monkeypatch.delenv(name, raising=False)


def test_default_profile_is_commercial() -> None:
    assert get_profile() is DeploymentProfile.COMMERCIAL


def test_scif_profile_is_recognised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIXOPS_PROFILE", "SCIF")  # case-insensitive
    assert get_profile() is DeploymentProfile.SCIF


def test_unknown_profile_refuses_rather_than_defaulting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A typo must not silently become 'commercial'.

    This is the dangerous failure: FIXOPS_PROFILE=SCIFF looks air-gapped to whoever set
    it, and would run with egress wide open.
    """
    monkeypatch.setenv("FIXOPS_PROFILE", "sciff")
    with pytest.raises(ProfileViolation, match="not a known profile"):
        get_profile()


def test_commercial_permits_cloud_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    validate_profile(DeploymentProfile.COMMERCIAL)  # must not raise


@pytest.mark.parametrize("key", ["OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"])
def test_scif_refuses_when_a_cloud_key_is_configured(
    monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    monkeypatch.setenv("FIXOPS_PROFILE", "scif")
    monkeypatch.setenv("FIXOPS_AIRGAP_MODE", "enforced")
    monkeypatch.setenv(key, "sk-test")

    with pytest.raises(ProfileViolation) as caught:
        validate_profile()

    assert key in str(caught.value)


def test_scif_refuses_when_egress_guard_is_not_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FIXOPS_PROFILE", "scif")
    monkeypatch.setenv("FIXOPS_AIRGAP_MODE", "detected")  # present but not enforcing

    with pytest.raises(ProfileViolation, match="not 'enforced'"):
        validate_profile()


def test_scif_reports_every_problem_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """An operator should not have to fix one violation to discover the next."""
    monkeypatch.setenv("FIXOPS_PROFILE", "scif")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    # airgap mode left unset as well

    with pytest.raises(ProfileViolation) as caught:
        validate_profile()

    message = str(caught.value)
    assert "OPENAI_API_KEY" in message
    assert "FIXOPS_AIRGAP_MODE" in message


def test_apply_defaults_turns_on_the_guards_for_scif(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os

    monkeypatch.setenv("FIXOPS_PROFILE", "scif")
    profile = apply_profile_defaults()

    assert profile is DeploymentProfile.SCIF
    assert os.environ["FIXOPS_AIRGAP_MODE"] == "enforced"
    assert os.environ["FIPS_MODE"] == "enforced"


def test_apply_defaults_never_relaxes_an_explicit_setting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An operator may be stricter than the profile; the profile may not loosen them."""
    import os

    monkeypatch.setenv("FIXOPS_PROFILE", "commercial")
    monkeypatch.setenv("FIXOPS_AIRGAP_MODE", "enforced")

    apply_profile_defaults()

    assert os.environ["FIXOPS_AIRGAP_MODE"] == "enforced"


def test_apply_defaults_still_validates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Filling in defaults must not paper over a genuine conflict."""
    monkeypatch.setenv("FIXOPS_PROFILE", "scif")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")

    with pytest.raises(ProfileViolation):
        apply_profile_defaults()


def test_cloud_key_detection_ignores_blank_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """An exported-but-empty variable is not a usable credential."""
    monkeypatch.setenv("OPENAI_API_KEY", "   ")
    assert cloud_llm_keys_present() == []


def test_posture_differs_between_profiles() -> None:
    commercial = profile_posture(DeploymentProfile.COMMERCIAL)
    scif = profile_posture(DeploymentProfile.SCIF)
    assert commercial["egress"] != scif["egress"]
    assert scif["council"] == "local inference only"
