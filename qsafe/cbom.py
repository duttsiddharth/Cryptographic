"""CycloneDX 1.6 cryptographic bill of materials.

The DST roadmap recommends a mandatory cryptographic BOM in government RFPs.
CycloneDX 1.6 is the format that carries `cryptographic-asset` components, so
that is what this emits — a machine-readable inventory a procuring authority
can diff between releases.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from .algorithms import Risk
from .risk import Assessment

PRIMITIVE = {
    "asymmetric": "pke",
    "symmetric": "block-cipher",
    "hash": "hash",
    "mac": "mac",
    "kdf": "key-derive",
    "pqc": "kem",
    "unknown": "other",
}

# CycloneDX expects a NIST security-strength band.
STRENGTH = {
    Risk.CLASSICALLY_BROKEN: 0,
    Risk.BROKEN_BY_QUANTUM: 0,
    Risk.WEAKENED_BY_QUANTUM: 128,
    Risk.QUANTUM_SAFE: 256,
    Risk.UNKNOWN: 0,
}


def _bom_ref(algorithm: str, path: str, line: int) -> str:
    digest = hashlib.sha256(f"{algorithm}:{path}:{line}".encode()).hexdigest()[:16]
    return f"crypto/{algorithm.lower().replace(' ', '-')}/{digest}"


def build_cbom(assessment: Assessment) -> dict:
    components = []
    for item in assessment.items:
        finding = item.finding
        properties = [
            {"name": "qsafe:rule", "value": finding.rule_id},
            {"name": "qsafe:confidence", "value": finding.confidence},
            {"name": "qsafe:quantum-risk", "value": item.risk.value},
            {"name": "qsafe:priority", "value": item.priority},
            {"name": "qsafe:location", "value": f"{finding.path}:{finding.line}"},
        ]
        if item.replacement:
            properties.append({"name": "qsafe:replacement", "value": item.replacement})
        if item.nist_standard:
            properties.append({"name": "qsafe:nist-standard", "value": item.nist_standard})
        for key, value in finding.detail.items():
            properties.append({"name": f"qsafe:{key}", "value": str(value)})

        algorithm_properties: dict = {
            "primitive": PRIMITIVE.get(item.family, "other"),
            "executionEnvironment": "unknown",
            "implementationPlatform": "generic",
            "nistQuantumSecurityLevel": STRENGTH[item.risk],
        }
        if finding.key_size:
            algorithm_properties["parameterSetIdentifier"] = str(finding.key_size)

        components.append({
            "type": "cryptographic-asset",
            "bom-ref": _bom_ref(finding.algorithm, finding.path, finding.line),
            "name": finding.algorithm,
            "description": item.rationale,
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": algorithm_properties,
                "oid": "",
            },
            "properties": properties,
            "evidence": {
                "occurrences": [
                    {"location": finding.path, "line": finding.line}
                ]
            },
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {"type": "application", "name": "qsafe", "version": "1.0.0"}
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": "target",
                "name": assessment.profile.organisation,
                "description": f"Cryptographic inventory of {assessment.scanned_path}",
            },
            "properties": [
                {"name": "qsafe:sector", "value": assessment.profile.sector},
                {"name": "qsafe:readiness-score", "value": str(assessment.readiness_score)},
                {"name": "qsafe:data-lifetime-years",
                 "value": str(assessment.profile.data_lifetime_years)},
                {"name": "qsafe:migration-years",
                 "value": str(assessment.profile.migration_years)},
                {"name": "qsafe:assumed-crqc-year",
                 "value": str(assessment.profile.crqc_year)},
                {"name": "qsafe:mosca-exposure-years",
                 "value": str(assessment.profile.mosca_exposure)},
                {"name": "qsafe:critical-infrastructure",
                 "value": str(assessment.profile.is_critical_infrastructure).lower()},
            ],
        },
        "components": components,
    }
