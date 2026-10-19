"""
scripts/simulate_security_scenarios.py

End-to-end production verification harness executing Scenarios A through E
against the native FastAPI ASGI application, fully aligned with app.domain.models.enums.
"""

import asyncio
from decimal import Decimal, ROUND_HALF_UP
import json
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
from app.main import app
from app.domain.models.enums import (
    DetectionSeverity,
    DetectionSourceType,
    EndpointClass,
    RiskCategory,
)
from tests.security.test_rbac import create_mock_jwt_token, SystemRole

# Authenticated token with write & read scopes
AUTH_TOKEN = create_mock_jwt_token(
    roles=[SystemRole.SECURITY_ADMIN],
    scopes=["assessments:read", "assessments:write"],
)
HEADERS = {
    "Authorization": f"Bearer {AUTH_TOKEN}",
    "Content-Type": "application/json",
}


def verify_formula_and_category(components: dict, reported_score: float, reported_rating: str) -> None:
    """Verifies that R = 0.4B + 0.3F + 0.2S + 0.1H strictly holds within 0.1 decimal rounding."""
    b = Decimal(str(components.get("behavior", 0.0)))
    f = Decimal(str(components.get("frequency", 0.0)))
    s = Decimal(str(components.get("sensitivity", 0.0)))
    h = Decimal(str(components.get("history", 0.0)))

    expected_score = (
        (Decimal("0.4") * b)
        + (Decimal("0.3") * f)
        + (Decimal("0.2") * s)
        + (Decimal("0.1") * h)
    ).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    actual_score = Decimal(str(reported_score)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)

    assert expected_score == actual_score, (
        f"Formula Mismatch: 0.4({b}) + 0.3({f}) + 0.2({s}) + 0.1({h}) = "
        f"{expected_score} != {actual_score}"
    )

    # Threshold intervals mapped directly to RiskCategory definitions
    if actual_score < Decimal("40.0"):
        expected_cat = RiskCategory.LOW.value
    elif actual_score < Decimal("65.0"):
        expected_cat = RiskCategory.MEDIUM.value
    elif actual_score < Decimal("85.0"):
        expected_cat = RiskCategory.HIGH.value
    else:
        expected_cat = RiskCategory.CRITICAL.value

    assert reported_rating.upper() == expected_cat, (
        f"Category Invariance Failed: Score {actual_score} mapped to "
        f"{reported_rating}, expected {expected_cat}"
    )


async def run_scenario(client: AsyncClient, name: str, payload: dict) -> dict:
    print("\n" + "=" * 80)
    print(f"▶ EXECUTING: {name}")
    print("=" * 80)

    resp = await client.post("/api/v1/risk-assessments", json=payload, headers=HEADERS)
    if resp.status_code not in (200, 201):
        print(f"❌ Execution failed with HTTP {resp.status_code}")
        print(f"Response Body: {resp.text}")
        raise RuntimeError(f"Scenario failed: {name}")

    data = resp.json()
    comp = data.get("components", {})
    score = data.get("risk_score")
    rating = data.get("rating")
    assessment_id = data.get("assessment_id")

    print(f"  • Assessment ID : {assessment_id}")
    print(
        f"  • Components    : Behavior={comp.get('behavior')} | "
        f"Freq={comp.get('frequency')} | Sens={comp.get('sensitivity')} | "
        f"Hist={comp.get('history')}"
    )
    print(f"  • Computed Score: {score}")
    print(f"  • Rating Tier   : {rating}")

    verify_formula_and_category(comp, score, rating)
    print("  ✅ Mathematical decomposition and rating boundaries verified.")
    return data


async def main():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:

        # ----------------------------------------------------------------------
        # Scenario A: Repeated Failed Logins (Brute Force / Password Spray)
        # Using DetectionSourceType.SIEM and EndpointClass.INTERNAL_SERVER
        # ----------------------------------------------------------------------
        cid_a = str(uuid4())
        scenario_a_payload = {
            "detection_event": {
                "correlation_id": cid_a,
                "source_type": DetectionSourceType.SIEM.value,
                "severity": DetectionSeverity.HIGH.value,
                "metrics": {"confidence": 92.0},
                "context": {
                    "source_ip": "192.0.2.45",
                    "rule_id": "AUTH-BRUTEFORCE-001",
                    "rule_name": "Multiple Consecutive Authentication Failures",
                    "username": "victim.user",
                },
            },
            "investigation_result": {
                "telemetry": {
                    "event_frequency": 40,
                    "historical_incident_count": 0,
                    "severity_hint": 75.0,
                    "endpoint_class": EndpointClass.INTERNAL_SERVER.value,
                },
                "touched_endpoints_detail": [
                    {
                        "endpoint_id": "auth-srv-01",
                        "endpoint_class": EndpointClass.INTERNAL_SERVER.value,
                        "is_compromised": False,
                    }
                ],
            },
        }
        await run_scenario(client, "Scenario A: Repeated Failed Logins", scenario_a_payload)

        # ----------------------------------------------------------------------
        # Scenario B: Suspected Lateral Movement
        # Using DetectionSourceType.EDR, DOMAIN_CONTROLLER, and DATABASE_SERVER
        # ----------------------------------------------------------------------
        cid_b = str(uuid4())
        scenario_b_payload = {
            "detection_event": {
                "correlation_id": cid_b,
                "source_type": DetectionSourceType.EDR.value,
                "severity": DetectionSeverity.HIGH.value,
                "metrics": {"confidence": 88.0},
                "context": {
                    "source_ip": "10.0.15.102",
                    "rule_id": "LATERAL-WMI-SMB-004",
                    "rule_name": "Unusual Internal Remote Service Execution",
                },
            },
            "investigation_result": {
                "telemetry": {
                    "event_frequency": 6,
                    "historical_incident_count": 1,
                    "endpoint_class": EndpointClass.DOMAIN_CONTROLLER.value,
                },
                "touched_endpoints_detail": [
                    {
                        "endpoint_id": "wkstn-user-09",
                        "endpoint_class": EndpointClass.WORKSTATION.value,
                        "is_compromised": True,
                    },
                    {
                        "endpoint_id": "db-core-prod",
                        "endpoint_class": EndpointClass.DATABASE_SERVER.value,
                        "is_compromised": False,
                    },
                    {
                        "endpoint_id": "dc-root-primary",
                        "endpoint_class": EndpointClass.DOMAIN_CONTROLLER.value,
                        "is_compromised": True,
                    },
                ],
            },
        }
        await run_scenario(client, "Scenario B: Suspected Lateral Movement", scenario_b_payload)

        # ----------------------------------------------------------------------
        # Scenario C: Suspicious Executable / Malware Alert
        # Using DetectionSeverity.CRITICAL and EndpointClass.CRITICAL_INFRASTRUCTURE
        # ----------------------------------------------------------------------
        cid_c = str(uuid4())
        scenario_c_payload = {
            "detection_event": {
                "correlation_id": cid_c,
                "source_type": DetectionSourceType.EDR.value,
                "severity": DetectionSeverity.CRITICAL.value,
                "metrics": {"confidence": 98.0, "fidelity": 0.95},
                "context": {
                    "source_ip": "10.0.8.21",
                    "rule_id": "MALWARE-PROCESS-HOLLOW-012",
                    "rule_name": "Memory Injection and Process Hollowing Detection",
                },
            },
            "investigation_result": {
                "telemetry": {
                    "event_frequency": 1,
                    "historical_incident_count": 0,
                    "severity_hint": 95.0,
                    "endpoint_class": EndpointClass.CRITICAL_INFRASTRUCTURE.value,
                },
                "touched_endpoints_detail": [
                    {
                        "endpoint_id": "scada-gw-01",
                        "endpoint_class": EndpointClass.CRITICAL_INFRASTRUCTURE.value,
                        "is_compromised": True,
                    }
                ],
            },
        }
        await run_scenario(client, "Scenario C: Malware / Code Injection Alert", scenario_c_payload)

        # ----------------------------------------------------------------------
        # Scenario D: Web Application Attack (SQLi / WAF Alert)
        # Using DetectionSourceType.APP_LOG and EndpointClass.INTERNAL_SERVER
        # ----------------------------------------------------------------------
        cid_d = str(uuid4())
        scenario_d_payload = {
            "detection_event": {
                "correlation_id": cid_d,
                "source_type": DetectionSourceType.APP_LOG.value,
                "severity": DetectionSeverity.MEDIUM.value,
                "metrics": {"confidence": 90.0},
                "context": {
                    "source_ip": "198.51.100.77",
                    "rule_id": "WAF-RULE-SQLI-942100",
                    "rule_name": "SQL Injection Attack Attempt Blocked",
                    "raw_payload": {"attack_vector": "1' OR '1'='1", "sanitized": True},
                },
            },
            "investigation_result": {
                "telemetry": {
                    "event_frequency": 3,
                    "historical_incident_count": 0,
                    "severity_hint": 60.0,
                    "endpoint_class": EndpointClass.INTERNAL_SERVER.value,
                },
                "touched_endpoints_detail": [
                    {
                        "endpoint_id": "waf-edge-proxy",
                        "endpoint_class": EndpointClass.INTERNAL_SERVER.value,
                        "is_compromised": False,
                    }
                ],
            },
        }
        res_d = await run_scenario(client, "Scenario D: Web App Injection Attempt", scenario_d_payload)

        # Verify raw payload isolation in response
        assert "1' OR '1'='1" not in json.dumps(res_d), (
            "Safety Violation: Raw exploit payload leaked in assessment response!"
        )
        print("  🔒 Payload hygiene verified: Exploit payload is not reflected in assessment output.")

        # ----------------------------------------------------------------------
        # Scenario E: Repeat Offender Differential History Check
        # Using DetectionSourceType.IDS_IPS and EndpointClass.WORKSTATION
        # ----------------------------------------------------------------------
        print("\n" + "=" * 80)
        print("▶ EXECUTING: Scenario E: Repeat Offender Baseline vs Delta Check")
        print("=" * 80)

        base_event = {
            "source_type": DetectionSourceType.IDS_IPS.value,
            "severity": DetectionSeverity.HIGH.value,
            "metrics": {"confidence": 85.0},
            "context": {
                "source_ip": "203.0.113.88",
                "rule_id": "NET-SCAN-C2-BEACON",
                "rule_name": "Repeated Outbound Beaconing Activity",
            },
        }

        # Run 1: History = 0
        cid_e1 = str(uuid4())
        p_e1 = {
            "detection_event": {"correlation_id": cid_e1, **base_event},
            "investigation_result": {
                "telemetry": {
                    "event_frequency": 12,
                    "historical_incident_count": 0,
                    "endpoint_class": EndpointClass.WORKSTATION.value,
                }
            },
        }
        r_e1 = await client.post("/api/v1/risk-assessments", json=p_e1, headers=HEADERS)
        data_e1 = r_e1.json()

        # Run 2: History = 5
        cid_e2 = str(uuid4())
        p_e2 = {
            "detection_event": {"correlation_id": cid_e2, **base_event},
            "investigation_result": {
                "telemetry": {
                    "event_frequency": 12,
                    "historical_incident_count": 5,
                    "endpoint_class": EndpointClass.WORKSTATION.value,
                }
            },
        }
        r_e2 = await client.post("/api/v1/risk-assessments", json=p_e2, headers=HEADERS)
        data_e2 = r_e2.json()

        comp1 = data_e1["components"]
        comp2 = data_e2["components"]

        print(
            f"  • Assessment 1 (Hist=0): Score={data_e1['risk_score']} | "
            f"H={comp1.get('history')} | Rating={data_e1['rating']}"
        )
        print(
            f"  • Assessment 2 (Hist=5): Score={data_e2['risk_score']} | "
            f"H={comp2.get('history')} | Rating={data_e2['rating']}"
        )

        # Validate component isolation
        assert comp1["behavior"] == comp2["behavior"], (
            "Isolation Failure: Behavior sub-score drifted between identical detections!"
        )
        assert comp1["frequency"] == comp2["frequency"], (
            "Isolation Failure: Frequency sub-score drifted between identical telemetry!"
        )
        assert comp1["sensitivity"] == comp2["sensitivity"], (
            "Isolation Failure: Sensitivity sub-score drifted!"
        )
        assert comp2["history"] > comp1["history"], (
            f"History Failure: Elevated incidents did not increase H "
            f"({comp2['history']} <= {comp1['history']})"
        )

        # Mathematical delta check
        delta_h = Decimal(str(comp2["history"])) - Decimal(str(comp1["history"]))
        expected_score_delta = (Decimal("0.1") * delta_h).quantize(
            Decimal("0.1"), rounding=ROUND_HALF_UP
        )
        actual_score_delta = (
            Decimal(str(data_e2["risk_score"])) - Decimal(str(data_e1["risk_score"]))
        ).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)

        print(
            f"  • ΔH = {delta_h} -> Expected Score Shift (0.1 * ΔH): {expected_score_delta} | "
            f"Actual Shift: {actual_score_delta}"
        )
        assert abs(actual_score_delta - expected_score_delta) <= Decimal("0.1"), (
            "Score shift does not match the 0.1 weight contribution!"
        )
        print("  ✅ Differential calculation verified: Only history shifted the final score.")

    print("\n🎉 ALL 5 PRODUCTION SCENARIOS PASSED FULL MATHEMATICAL VERIFICATION!")


if __name__ == "__main__":
    asyncio.run(main())