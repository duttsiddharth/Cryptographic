"""Run with: python -m pytest -q"""

from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from qsafe.algorithms import Risk, lookup, unknown
from qsafe.cbom import build_cbom
from qsafe.cli import main
from qsafe.report import render
from qsafe.risk import Profile, assess
from qsafe.scanner import Finding, scan

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "legacy-bank"


def _certificate(path: Path, key, cn: str) -> None:
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Bank"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name)
                   .public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now)
                   .not_valid_after(now + datetime.timedelta(days=365))
                   .sign(key, hashes.SHA256()))
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


# -- catalogue ---------------------------------------------------------------


def test_asymmetric_algorithms_are_quantum_broken():
    for name in ("RSA", "ECDSA", "ECDH", "Ed25519", "X25519", "DSA", "DH"):
        assert lookup(name).risk is Risk.BROKEN_BY_QUANTUM, name


def test_aes_256_is_safe_but_aes_128_is_weakened():
    assert lookup("AES-256").risk is Risk.QUANTUM_SAFE
    assert lookup("AES-128").risk is Risk.WEAKENED_BY_QUANTUM
    assert lookup("AES-128").replacement == "AES-256"


def test_pqc_algorithms_are_safe_and_cite_a_standard():
    for name in ("ML-KEM", "ML-DSA", "SLH-DSA"):
        algorithm = lookup(name)
        assert algorithm.risk is Risk.QUANTUM_SAFE
        assert algorithm.nist_standard


def test_unknown_algorithm_falls_back_without_raising():
    algorithm = unknown("SomeVendorCipher")
    assert algorithm.risk is Risk.UNKNOWN


# -- scanning ----------------------------------------------------------------


def test_scan_finds_python_java_and_js_usage():
    findings = scan(SAMPLE / "src")
    algorithms = {f.algorithm for f in findings}
    assert {"RSA", "ECDSA", "MD5", "SHA-1", "SHA-256", "3DES"} <= algorithms


def test_scan_reads_tls_configuration():
    findings = scan(SAMPLE / "config")
    algorithms = {f.algorithm for f in findings}
    assert "ECDH" in algorithms
    assert "AES-128" in algorithms
    assert "3DES" in algorithms


def test_scan_parses_real_certificates(tmp_path):
    weak = tmp_path / "weak.pem"
    _certificate(weak, rsa.generate_private_key(public_exponent=65537, key_size=1024), "weak")
    strong = tmp_path / "strong.pem"
    _certificate(strong, rsa.generate_private_key(public_exponent=65537, key_size=3072), "strong")
    curve = tmp_path / "curve.pem"
    _certificate(curve, ec.generate_private_key(ec.SECP256R1()), "curve")

    findings = scan(tmp_path)
    by_path = {Path(f.path).name: f for f in findings if f.rule_id == "CERT-PARSE-001"}
    assert by_path["weak.pem"].key_size == 1024
    assert by_path["strong.pem"].key_size == 3072
    assert by_path["curve.pem"].algorithm == "ECDSA"
    assert all(f.confidence == "certain" for f in by_path.values())


def test_scan_flags_an_unencrypted_private_key(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    target = tmp_path / "service.key"
    target.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    findings = scan(tmp_path)
    assert any(f.rule_id == "KEY-PARSE-001" and f.key_size == 2048 for f in findings)


def test_commented_code_is_downgraded_to_low_confidence(tmp_path):
    (tmp_path / "old.py").write_text("# rsa.generate_private_key(key_size=2048)\n")
    findings = scan(tmp_path)
    assert findings and all(f.confidence == "low" for f in findings)


def test_scan_skips_vendor_directories(tmp_path):
    vendored = tmp_path / "node_modules" / "pkg"
    vendored.mkdir(parents=True)
    (vendored / "a.js").write_text("crypto.createHash('md5')\n")
    (tmp_path / "app.js").write_text("crypto.createHash('md5')\n")
    findings = scan(tmp_path)
    assert len(findings) == 1
    assert "node_modules" not in findings[0].path


def test_scan_rejects_a_missing_path():
    with pytest.raises(FileNotFoundError):
        scan("/no/such/directory")


# -- risk --------------------------------------------------------------------


def test_mosca_inequality_detects_exposure():
    exposed = Profile(data_lifetime_years=25, migration_years=5, crqc_year=2035)
    assert exposed.mosca_breached
    assert exposed.mosca_exposure > 0

    comfortable = Profile(data_lifetime_years=2, migration_years=1, crqc_year=2060)
    assert not comfortable.mosca_breached


def test_critical_infrastructure_gets_the_earlier_deadline():
    assert Profile(is_critical_infrastructure=True).deadline_year == 2027
    assert Profile(is_critical_infrastructure=False).deadline_year == 2029
    assert Profile(is_critical_infrastructure=True, migration_years=3).start_by_year == 2024


def test_weak_rsa_is_reclassified_as_broken_today():
    finding = Finding(path="a.pem", line=0, algorithm="RSA", rule_id="CERT-PARSE-001",
                      description="cert", confidence="certain", evidence="cn",
                      key_size=1024)
    assessment = assess([finding], Profile(), "a.pem")
    assert assessment.items[0].risk is Risk.CLASSICALLY_BROKEN
    assert assessment.items[0].priority == "immediate"


def test_strong_rsa_stays_a_quantum_problem_not_a_classical_one():
    finding = Finding(path="a.pem", line=0, algorithm="RSA", rule_id="CERT-PARSE-001",
                      description="cert", confidence="certain", evidence="cn",
                      key_size=3072)
    assessment = assess([finding], Profile(), "a.pem")
    assert assessment.items[0].risk is Risk.BROKEN_BY_QUANTUM


def test_readiness_score_rewards_a_clean_estate():
    safe = [Finding("a.py", 1, "AES-256", "R", "d", "high", "e"),
            Finding("b.py", 1, "ML-KEM", "R", "d", "high", "e")]
    assert assess(safe, Profile(), ".").readiness_score == 100

    broken = [Finding("a.py", 1, "MD5", "R", "d", "high", "e")]
    assert assess(broken, Profile(), ".").readiness_score == 0


def test_findings_are_ordered_worst_first():
    findings = [
        Finding("a.py", 1, "AES-256", "R1", "d", "high", "e"),
        Finding("b.py", 1, "MD5", "R2", "d", "high", "e"),
        Finding("c.py", 1, "RSA", "R3", "d", "high", "e"),
    ]
    items = assess(findings, Profile(), ".").items
    assert [i.finding.algorithm for i in items] == ["MD5", "RSA", "AES-256"]


def test_low_confidence_findings_score_below_certain_ones():
    certain = assess([Finding("a", 1, "RSA", "R", "d", "certain", "e")], Profile(), ".")
    guessed = assess([Finding("a", 1, "RSA", "R", "d", "low", "e")], Profile(), ".")
    assert certain.items[0].score > guessed.items[0].score


# -- outputs -----------------------------------------------------------------


def test_cbom_is_valid_cyclonedx_with_crypto_assets():
    findings = scan(SAMPLE)
    assessment = assess(findings, Profile(organisation="Sample Bank"), str(SAMPLE))
    bom = build_cbom(assessment)

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["components"]
    for component in bom["components"]:
        assert component["type"] == "cryptographic-asset"
        assert component["cryptoProperties"]["assetType"] == "algorithm"
        assert component["bom-ref"]
        assert component["evidence"]["occurrences"]
    # round-trips as JSON
    json.loads(json.dumps(bom))


def test_report_renders_and_names_the_findings():
    findings = scan(SAMPLE)
    assessment = assess(findings, Profile(organisation="Sample Bank", sector="banking"),
                        str(SAMPLE))
    output = render(assessment)
    assert output.startswith("<!DOCTYPE html>")
    assert "Sample Bank" in output
    assert "Mosca" in output
    assert "readiness score" in output
    assert "<script" not in output.lower()


def test_report_escapes_hostile_content(tmp_path):
    (tmp_path / "evil.py").write_text(
        'hashlib.md5(b"")  # <img src=x onerror="alert(1)">\n')
    assessment = assess(scan(tmp_path), Profile(), str(tmp_path))
    output = render(assessment)
    # The angle brackets and quotes are neutralised, so no tag is ever formed.
    assert "<img" not in output
    assert '<img src=x onerror="alert(1)">' not in output
    assert "&lt;img" in output


# -- CLI ---------------------------------------------------------------------


def test_cli_writes_all_three_artefacts(tmp_path):
    outdir = tmp_path / "out"
    code = main([str(SAMPLE), "-o", str(outdir), "--org", "Sample Bank", "--quiet"])
    assert code == 0
    assert (outdir / "readiness-report.html").exists()
    assert (outdir / "cbom.json").exists()
    assert (outdir / "findings.json").exists()

    payload = json.loads((outdir / "findings.json").read_text())
    assert payload["organisation"] == "Sample Bank"
    assert payload["findings"]
    assert 0 <= payload["readiness_score"] <= 100


def test_cli_fail_on_gates_a_build(tmp_path):
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "ok.py").write_text("from qsafe import nothing\n")
    assert main([str(clean), "-o", str(tmp_path / "a"), "--quiet", "--fail-on", "high"]) == 0

    dirty = tmp_path / "dirty"
    dirty.mkdir()
    (dirty / "bad.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    assert main([str(dirty), "-o", str(tmp_path / "b"), "--quiet", "--fail-on", "immediate"]) == 1


def test_cli_returns_two_for_a_missing_path(tmp_path, capsys):
    assert main(["/no/such/path", "-o", str(tmp_path), "--quiet"]) == 2


def test_cli_honours_the_crqc_assumption(tmp_path):
    outdir = tmp_path / "out"
    main([str(SAMPLE), "-o", str(outdir), "--quiet", "--data-lifetime", "30",
          "--migration-years", "5", "--crqc-year", "2032", "--critical-infrastructure"])
    payload = json.loads((outdir / "findings.json").read_text())
    assert payload["mosca"]["breached"] is True
    assert payload["deadline_year"] == 2027
