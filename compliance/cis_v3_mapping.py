"""CIS AWS Foundations Benchmark v3.0.0 control mapping — Phase 1.

Exactly 4 controls, chosen because they map to findings
kdavis-cloud-audit's AWSProvider already produces today (see
audit/providers/aws.py's _collect_iam) -- no new scanning code needed.
See CLAUDE.md for the full "why CIS-only, why v3.0.0" reasoning and why
the other ~58 CIS v3.0.0 controls are explicitly NOT covered here.

Security Hub control IDs and CIS control numbers below were confirmed
against AWS's own Security Hub CIS AWS Foundations Benchmark
documentation (fetched live 2026-09-11), not recalled from training data
-- getting a compliance control number wrong is a real integrity risk if
a customer relies on this for an actual audit.

Each entry's `match(findings)` returns True (PASS) when none of the
findings it's watching for are present in this scan's sanitized findings
list. `exact_match` is False where AWSProvider's finding is a
conservative proxy for the control rather than a precise 1:1 check --
callers (gap_report.py) surface that caveat, they must never silently
present a proxy as an exact verification.
"""

from typing import Callable, TypedDict


class CisControl(TypedDict):
    control_id: str
    security_hub_id: str
    title: str
    exact_match: bool
    caveat: str | None
    match: Callable[[list[dict]], bool]


def _no_finding_titled(title: str) -> Callable[[list[dict]], bool]:
    def _match(findings: list[dict]) -> bool:
        return not any(f.get("title") == title for f in findings)

    return _match


def _no_finding_title_startswith(prefix: str) -> Callable[[list[dict]], bool]:
    def _match(findings: list[dict]) -> bool:
        return not any(str(f.get("title", "")).startswith(prefix) for f in findings)

    return _match


CIS_V3_CONTROLS: list[CisControl] = [
    {
        "control_id": "1.4",
        "security_hub_id": "IAM.4",
        "title": "IAM root user access key should not exist",
        "exact_match": True,
        "caveat": None,
        "match": _no_finding_titled("Root account has active access keys"),
    },
    {
        "control_id": "1.5",
        "security_hub_id": "IAM.9",
        "title": "MFA should be enabled for the root user",
        "exact_match": True,
        "caveat": None,
        "match": _no_finding_titled("Root account has no MFA"),
    },
    {
        "control_id": "1.10",
        "security_hub_id": "IAM.5",
        "title": "MFA should be enabled for all IAM users that have a console password",
        "exact_match": False,
        "caveat": (
            "AWSProvider flags any IAM user with no MFA device at all -- it "
            "cannot determine whether a given user actually has a console "
            "password (vs. programmatic-access-only). This is a "
            "conservative proxy: it may flag users this specific CIS "
            "control does not technically require MFA for."
        ),
        "match": _no_finding_title_startswith("User has no MFA device"),
    },
    {
        "control_id": "1.14",
        "security_hub_id": "IAM.3",
        "title": "IAM users' access keys should be rotated every 90 days or less",
        "exact_match": True,
        "caveat": None,
        "match": _no_finding_title_startswith("Access key not rotated in"),
    },
]

# Confirmed via AWS's own CIS AWS Foundations Benchmark v3.0.0 documentation.
CIS_V3_TOTAL_CONTROLS = 62
