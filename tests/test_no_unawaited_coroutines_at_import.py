"""Regression lockdown: importing core engines must not produce unawaited-coroutine warnings.

Originally caught at endpoint mount verification (commit 2ad076c1) and fixed at 1b25903a.
"""
import importlib
import warnings
import pytest

ENGINES = [
    "core.aws_securityhub_engine",
    "core.amazon_inspector_engine",
    "core.aws_iam_engine",
    "core.proofpoint_tap_engine",
    "core.datadog_security_engine",
    "core.defender_xdr_engine",
    "core.newrelic_apm_engine",
    "core.terraform_cloud_engine",
    "core.slack_chatops_engine",
    "core.aws_waf_engine",
]

@pytest.mark.parametrize("module_name", ENGINES)
def test_engine_imports_without_unawaited_coroutine_warning(module_name: str) -> None:
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("error", RuntimeWarning)
        try:
            importlib.import_module(module_name)
        except RuntimeWarning as w:
            pytest.fail(f"{module_name} import raised RuntimeWarning: {w}")
