"""Builds a CIS AWS Foundations Benchmark v3.0.0 gap report from a scan's
sanitized findings.

Deterministic only -- no LLM call anywhere in this path. See
cis_v3_mapping.py and CLAUDE.md for why control pass/fail must never be
left to a model's judgment.
"""

from compliance.cis_v3_mapping import CIS_V3_CONTROLS, CIS_V3_TOTAL_CONTROLS

FRAMEWORK_NAME = "CIS AWS Foundations Benchmark v3.0.0"

_DOCUMENTATION_CHECKLIST = [
    {
        "item": "Information Security Policy",
        "status": "cannot_verify_from_scan",
        "guidance": "Must be authored and maintained manually -- no AWS API reflects whether this document exists.",
    },
    {
        "item": "Incident Response Plan",
        "status": "cannot_verify_from_scan",
        "guidance": "Must be authored and maintained manually.",
    },
    {
        "item": "Access Control Policy",
        "status": "cannot_verify_from_scan",
        "guidance": "Must be authored and maintained manually.",
    },
]


def build_gap_report(findings: list[dict]) -> dict:
    results = []
    for control in CIS_V3_CONTROLS:
        passed = control["match"](findings)
        results.append(
            {
                "control_id": control["control_id"],
                "security_hub_id": control["security_hub_id"],
                "title": control["title"],
                "status": "PASS" if passed else "FAIL",
                "exact_match": control["exact_match"],
                "caveat": control["caveat"],
            }
        )

    passing = sum(1 for r in results if r["status"] == "PASS")
    controls_assessed = len(results)

    return {
        "framework": FRAMEWORK_NAME,
        "controls_assessed": controls_assessed,
        "controls_total_in_framework": CIS_V3_TOTAL_CONTROLS,
        "readiness_score": round(passing / controls_assessed * 100) if controls_assessed else 0,
        "controls": results,
        "coverage_note": (
            f"This report automatically assesses {controls_assessed} of "
            f"{CIS_V3_TOTAL_CONTROLS} {FRAMEWORK_NAME} controls -- the ones "
            "this scan can verify from AWS API data alone. The remaining "
            "controls need either additional automated checks (planned, "
            "see EXECUTION_ORDER.md Phase 2) or manual review. The "
            "readiness score reflects only the assessed subset -- it is "
            "not a complete CIS assessment."
        ),
        "documentation_checklist": _DOCUMENTATION_CHECKLIST,
    }
