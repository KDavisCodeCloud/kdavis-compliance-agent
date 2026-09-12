"""CIS Microsoft Azure Foundations Benchmark v3.0.0 control mapping.

Exactly 4 controls, chosen because they map to findings
kdavis-cloud-audit's AzureProvider already produces
(see audit/providers/azure.py's _collect_storage_secure_transfer,
_collect_storage_public_access, _collect_nsg_open_management_ports) --
no new scanning code needed here, same "no scanning logic duplicated"
rule as the AWS mapping.

Unlike the AWS side, these checks do NOT depend on Microsoft Defender for
Cloud's Regulatory Compliance API -- that API requires the customer's
subscription to be on Defender's paid standard pricing tier (confirmed
live: a 400 "no standard pricing bundle" error on a subscription without
it). These are bespoke, Reader-scoped ARM API checks instead, matching
this portfolio's own AWS-side philosophy of self-contained checks that
work for any customer at zero extra cost.

Control text (Id, Description, Section, AssessmentStatus) below is sourced
from Prowler's open-source CIS Azure 3.0 compliance mapping
(https://raw.githubusercontent.com/prowler-cloud/prowler/master/prowler/compliance/azure/cis_3.0_azure.json,
fetched live 2026-09-12), not recalled from training data -- getting a
compliance control number wrong is a real integrity risk if a customer
relies on this for an actual audit. Total control count (159) is from
that same source's Requirements list.

A fifth candidate control, 6.1.1 ("Ensure that a 'Diagnostic Setting'
exists for Subscription Activity Logs"), was deliberately excluded: its
own AssessmentStatus in the CIS data is "Manual", not "Automated" like the
four below -- this repo never invents a pass/fail for a control that
isn't actually API-verifiable, same discipline that kept the AWS mapping
at 4 controls instead of guessing at 62.

Azure has no equivalent to AWS Security Hub's per-control ID scheme, so
`security_hub_id` is an empty string for every entry here -- there is no
cross-referenced service ID to put in it. Left as a field (not removed)
so gap_report.py's generic result-shape logic needs no changes.

Each entry's `match(findings)` returns True (PASS) when none of the
findings it's watching for are present in this scan's sanitized findings
list. All four are `exact_match: True` -- each is a direct, non-proxy ARM
property check (e.g. `enable_https_traffic_only is False`), not a
conservative approximation.
"""

from typing import Callable, TypedDict


class CisControl(TypedDict):
    control_id: str
    security_hub_id: str
    title: str
    exact_match: bool
    caveat: str | None
    match: Callable[[list[dict]], bool]


def _no_finding_title_startswith(prefix: str) -> Callable[[list[dict]], bool]:
    def _match(findings: list[dict]) -> bool:
        return not any(str(f.get("title", "")).startswith(prefix) for f in findings)

    return _match


CIS_AZURE_CONTROLS: list[CisControl] = [
    {
        "control_id": "4.1",
        "security_hub_id": "",
        "title": "Ensure that 'Secure transfer required' is set to 'Enabled'",
        "exact_match": True,
        "caveat": None,
        "match": _no_finding_title_startswith("CIS 4.1:"),
    },
    {
        "control_id": "4.17",
        "security_hub_id": "",
        "title": "Ensure that 'Allow Blob Anonymous Access' is set to 'Disabled'",
        "exact_match": True,
        "caveat": None,
        "match": _no_finding_title_startswith("CIS 4.17:"),
    },
    {
        "control_id": "7.1",
        "security_hub_id": "",
        "title": "Ensure that RDP access from the Internet is evaluated and restricted",
        "exact_match": True,
        "caveat": None,
        "match": _no_finding_title_startswith("CIS 7.1:"),
    },
    {
        "control_id": "7.2",
        "security_hub_id": "",
        "title": "Ensure that SSH access from the Internet is evaluated and restricted",
        "exact_match": True,
        "caveat": None,
        "match": _no_finding_title_startswith("CIS 7.2:"),
    },
]

# Confirmed via Prowler's own CIS Microsoft Azure Foundations Benchmark
# v3.0.0 compliance JSON (159 total Requirements), fetched live 2026-09-12.
CIS_AZURE_TOTAL_CONTROLS = 159

FRAMEWORK_NAME_AZURE = "CIS Microsoft Azure Foundations Benchmark v3.0.0"
