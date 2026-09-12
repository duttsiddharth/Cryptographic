"""qsafe command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .algorithms import RISK_LABEL, Risk
from .cbom import build_cbom
from .report import render
from .risk import Profile, assess
from .scanner import scan

PRIORITY_RANK = {"immediate": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qsafe",
        description="Cryptographic inventory and post-quantum readiness assessment.",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("-o", "--outdir", default="qsafe-output",
                        help="Where to write the report and CBOM (default: qsafe-output)")
    parser.add_argument("--org", default="Unnamed organisation",
                        help="Organisation name for the report")
    parser.add_argument("--sector", default="general",
                        help="Sector, e.g. banking, telecom, health, government")
    parser.add_argument("--data-lifetime", type=int, default=10, metavar="YEARS",
                        help="How long the data must stay confidential (default: 10)")
    parser.add_argument("--migration-years", type=int, default=3, metavar="YEARS",
                        help="Estimated migration duration (default: 3)")
    parser.add_argument("--crqc-year", type=int, default=2035, metavar="YEAR",
                        help="Assumed arrival of a cryptographically relevant quantum "
                             "computer (default: 2035)")
    parser.add_argument("--critical-infrastructure", action="store_true",
                        help="Apply the 2027 CII deadline instead of 2029")
    parser.add_argument("--limit", type=int, default=100,
                        help="Findings shown in the HTML report (default: 100)")
    parser.add_argument("--format", choices=["all", "report", "cbom", "json"],
                        default="all", help="What to write (default: all)")
    parser.add_argument("--fail-on", choices=["never", "immediate", "high", "medium", "low"],
                        default="never",
                        help="Exit non-zero if a finding at this priority or worse exists. "
                             "Use in CI to gate on new quantum-broken cryptography.")
    parser.add_argument("--quiet", action="store_true", help="Suppress the console summary")
    return parser


def _summarise(assessment) -> None:
    profile = assessment.profile
    counts = assessment.by_priority()
    risks = assessment.by_risk()

    print()
    print(f"  {profile.organisation} — {assessment.verdict.lower()}")
    print(f"  readiness score {assessment.readiness_score}/100 "
          f"across {len(assessment.items)} findings")
    print()
    for risk in (Risk.CLASSICALLY_BROKEN, Risk.BROKEN_BY_QUANTUM,
                 Risk.WEAKENED_BY_QUANTUM, Risk.UNKNOWN, Risk.QUANTUM_SAFE):
        count = risks.get(risk.value, 0)
        if count:
            print(f"    {RISK_LABEL[risk]:<24} {count}")
    print()
    print(f"    immediate {counts['immediate']} · high {counts['high']} · "
          f"medium {counts['medium']} · low {counts['low']}")

    if profile.mosca_breached:
        print()
        print(f"  Mosca's inequality is breached by {profile.mosca_exposure} years "
              f"({profile.data_lifetime_years} + {profile.migration_years} > "
              f"{profile.years_to_crqc}).")
        print("  Data encrypted today with a quantum-broken algorithm should be treated")
        print("  as already exposed to an adversary recording traffic.")

    print()
    print(f"  Binding deadline {profile.deadline_year}. "
          f"Start migration by {profile.start_by_year}.")

    top = [i for i in assessment.items if i.priority in ("immediate", "high")][:5]
    if top:
        print()
        print("  Worst first:")
        for item in top:
            where = (f"{item.finding.path}:{item.finding.line}"
                     if item.finding.line else item.finding.path)
            print(f"    [{item.priority:<9}] {item.finding.algorithm:<10} {where}")
    print()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        findings = scan(args.path)
    except FileNotFoundError as error:
        print(f"qsafe: {error}", file=sys.stderr)
        return 2

    profile = Profile(
        organisation=args.org,
        sector=args.sector,
        data_lifetime_years=args.data_lifetime,
        migration_years=args.migration_years,
        crqc_year=args.crqc_year,
        is_critical_infrastructure=args.critical_infrastructure,
    )
    assessment = assess(findings, profile, str(Path(args.path).resolve()))

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    if args.format in ("all", "report"):
        target = outdir / "readiness-report.html"
        target.write_text(render(assessment, limit=args.limit), encoding="utf-8")
        written.append(target)

    if args.format in ("all", "cbom"):
        target = outdir / "cbom.json"
        target.write_text(json.dumps(build_cbom(assessment), indent=2), encoding="utf-8")
        written.append(target)

    if args.format in ("all", "json"):
        target = outdir / "findings.json"
        target.write_text(json.dumps({
            "organisation": profile.organisation,
            "sector": profile.sector,
            "scanned": assessment.scanned_path,
            "generated_on": assessment.generated_on,
            "readiness_score": assessment.readiness_score,
            "verdict": assessment.verdict,
            "mosca": {
                "data_lifetime_years": profile.data_lifetime_years,
                "migration_years": profile.migration_years,
                "years_to_crqc": profile.years_to_crqc,
                "exposure_years": profile.mosca_exposure,
                "breached": profile.mosca_breached,
            },
            "deadline_year": profile.deadline_year,
            "start_by_year": profile.start_by_year,
            "counts": {"risk": assessment.by_risk(), "priority": assessment.by_priority()},
            "findings": [item.as_dict() for item in assessment.items],
        }, indent=2), encoding="utf-8")
        written.append(target)

    if not args.quiet:
        _summarise(assessment)
        for path in written:
            print(f"  wrote {path}")
        print()

    if args.fail_on != "never":
        threshold = PRIORITY_RANK[args.fail_on]
        breaching = [i for i in assessment.items
                     if PRIORITY_RANK.get(i.priority, 9) <= threshold]
        if breaching:
            if not args.quiet:
                print(f"  qsafe: {len(breaching)} finding(s) at or above "
                      f"'{args.fail_on}' priority", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
