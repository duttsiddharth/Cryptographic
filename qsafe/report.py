"""The report a CISO reads and a board sees one page of."""

from __future__ import annotations

import html
from datetime import date

from .algorithms import RISK_LABEL, Risk
from .risk import DST_MILESTONES, Assessment

RISK_COLOUR = {
    Risk.CLASSICALLY_BROKEN: ("#F7EBEB", "#9A2B2B", "#E0B9B9"),
    Risk.BROKEN_BY_QUANTUM: ("#FAEEE6", "#A8511C", "#E7C4A8"),
    Risk.WEAKENED_BY_QUANTUM: ("#F9F1DC", "#8A6A1F", "#E3D5AE"),
    Risk.QUANTUM_SAFE: ("#E8F2ED", "#1A6B4F", "#BFDACE"),
    Risk.UNKNOWN: ("#F1F4F7", "#4A576A", "#D6DCE4"),
}

PRIORITY_ORDER = ["immediate", "high", "medium", "low", "none"]

CSS = """
:root{--ink:#16202E;--soft:#4A576A;--faint:#8892A0;--paper:#F1F4F7;--rule:#D6DCE4;
--brass:#8A6A1F;--brass-wash:#F7F1E1;--green:#1A6B4F;--green-wash:#E8F2ED;
--red:#9A2B2B;--red-wash:#F7EBEB}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);
font:15px/1.6 "Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:0 32px 64px}
header{background:var(--ink);color:#fff;padding:34px 0 30px;margin-bottom:30px}
header .wrap{padding-bottom:0}
h1{font:500 28px/1.25 Georgia,serif;margin:0 0 6px}
h2{font:500 20px/1.3 Georgia,serif;margin:36px 0 14px}
h3{font:500 16px/1.3 Georgia,serif;margin:0 0 8px}
header p{margin:0;color:#9FB0C4;font-size:14px}
.panel{background:#fff;border:1px solid var(--rule);border-radius:3px;padding:22px 24px;margin-bottom:18px}
.score{display:flex;gap:30px;align-items:center;flex-wrap:wrap}
.dial{width:132px;height:132px;border-radius:50%;flex:none;display:flex;flex-direction:column;
align-items:center;justify-content:center;border:3px solid;text-align:center}
.dial b{font:500 38px/1 Georgia,serif}
.dial span{font-size:11.5px;margin-top:5px}
.score .body{flex:1;min-width:280px}
.stats{display:flex;gap:26px;flex-wrap:wrap;margin-top:14px}
.stats div b{display:block;font:500 24px/1.1 Georgia,serif}
.stats div span{font-size:12.5px;color:var(--faint)}
.pill{display:inline-block;padding:2px 9px;border-radius:2px;font-size:12px;border:1px solid;white-space:nowrap}
table{width:100%;border-collapse:collapse;font-size:13.5px;background:#fff}
th{text-align:left;font-weight:500;color:var(--faint);padding:9px 10px;border-bottom:1px solid var(--rule);font-size:12.5px}
td{padding:9px 10px;border-bottom:1px solid #E7EBF0;vertical-align:top}
tr:last-child td{border-bottom:0}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--paper);
padding:1px 5px;border-radius:2px;word-break:break-all}
.note{background:var(--brass-wash);border:1px solid #E3D5AE;border-radius:3px;padding:16px 20px;margin-bottom:18px}
.alarm{background:var(--red-wash);border-color:#E0B9B9}
.ok{background:var(--green-wash);border-color:#BFDACE}
ul{margin:8px 0 0;padding-left:20px}
li{margin-bottom:5px}
.muted{color:var(--soft);font-size:13px}
.bar{display:flex;height:9px;border-radius:2px;overflow:hidden;margin:14px 0 8px;background:var(--paper)}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12.5px;color:var(--soft)}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:6px}
footer{color:var(--faint);font-size:12.5px;margin-top:34px;border-top:1px solid var(--rule);padding-top:16px}
@media print{body{background:#fff}.panel,table{border-color:#ccc}}
"""


def _e(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _dial(score: int) -> str:
    if score >= 90:
        bg, fg, border = RISK_COLOUR[Risk.QUANTUM_SAFE]
    elif score >= 70:
        bg, fg, border = RISK_COLOUR[Risk.WEAKENED_BY_QUANTUM]
    elif score >= 40:
        bg, fg, border = RISK_COLOUR[Risk.BROKEN_BY_QUANTUM]
    else:
        bg, fg, border = RISK_COLOUR[Risk.CLASSICALLY_BROKEN]
    return (f'<div class="dial" style="background:{bg};border-color:{fg};color:{fg}">'
            f'<b>{score}</b><span>readiness score</span></div>')


def _risk_bar(assessment: Assessment) -> str:
    counts = assessment.by_risk()
    total = sum(counts.values()) or 1
    order = [Risk.CLASSICALLY_BROKEN, Risk.BROKEN_BY_QUANTUM,
             Risk.WEAKENED_BY_QUANTUM, Risk.UNKNOWN, Risk.QUANTUM_SAFE]
    segments, legend = [], []
    for risk in order:
        count = counts.get(risk.value, 0)
        if not count:
            continue
        _, fg, _ = RISK_COLOUR[risk]
        segments.append(f'<div style="width:{100 * count / total:.2f}%;background:{fg}"></div>')
        legend.append(f'<span><i style="background:{fg}"></i>{RISK_LABEL[risk]} · {count}</span>')
    return (f'<div class="bar">{"".join(segments)}</div>'
            f'<div class="legend">{"".join(legend)}</div>')


def _mosca(assessment: Assessment) -> str:
    profile = assessment.profile
    x, y = profile.data_lifetime_years, profile.migration_years
    z = profile.years_to_crqc
    if profile.mosca_breached:
        return (
            f'<div class="note alarm"><h3>Mosca\'s inequality is already breached</h3>'
            f'<p style="margin:0">Data must stay confidential for <b>{x} years</b> and '
            f'migration is estimated at <b>{y} years</b>, against <b>{z} years</b> before '
            f'a cryptographically relevant quantum computer is assumed to exist '
            f'({profile.crqc_year}). {x} + {y} = {x + y}, which exceeds {z} by '
            f'<b>{profile.mosca_exposure} years</b>.</p>'
            f'<p style="margin:10px 0 0">Anything encrypted today with a quantum-broken '
            f'algorithm should be treated as already disclosed to any adversary recording '
            f'traffic. Migration planning cannot wait for a hardware announcement.</p></div>'
        )
    return (
        f'<div class="note ok"><h3>Mosca\'s inequality holds, for now</h3>'
        f'<p style="margin:0">{x} + {y} = {x + y}, against {z} years before the assumed '
        f'arrival of a cryptographically relevant quantum computer ({profile.crqc_year}). '
        f'Headroom is <b>{abs(profile.mosca_exposure)} years</b>. This is sensitive to the '
        f'assumption — shorten the estimate by three years and the position reverses.</p></div>'
    )


def _milestones(assessment: Assessment) -> str:
    profile = assessment.profile
    this_year = date.today().year
    rows = []
    for year, text in DST_MILESTONES:
        if year < this_year:
            status, colour = "Elapsed", "#9A2B2B"
        elif year == this_year:
            status, colour = "Due this year", "#8A6A1F"
        else:
            status, colour = f"{year - this_year} years away", "#4A576A"
        rows.append(
            f"<tr><td style='width:70px'><b>{year}</b></td><td>{_e(text)}</td>"
            f"<td style='width:130px;color:{colour}'>{status}</td></tr>"
        )
    return (
        f"<table><thead><tr><th>Year</th><th>DST roadmap milestone</th><th>Status</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
        f"<p class='muted' style='margin-top:12px'>This organisation is classified as "
        f"<b>{'critical information infrastructure' if profile.is_critical_infrastructure else 'a general adopter'}</b>, "
        f"so the binding deadline is <b>{profile.deadline_year}</b>. At an estimated "
        f"{profile.migration_years}-year migration, work must begin no later than "
        f"<b>{profile.start_by_year}</b>.</p>"
    )


def _findings_table(assessment: Assessment, limit: int) -> str:
    rows = []
    for item in assessment.items[:limit]:
        bg, fg, border = RISK_COLOUR[item.risk]
        finding = item.finding
        location = f"{finding.path}:{finding.line}" if finding.line else finding.path
        rows.append(
            f"<tr>"
            f"<td><span class='pill' style='background:{bg};color:{fg};border-color:{border}'>"
            f"{_e(item.priority)}</span></td>"
            f"<td><b>{_e(finding.algorithm)}</b>"
            + (f"<div class='muted'>{finding.key_size} bits</div>" if finding.key_size else "")
            + f"</td>"
            f"<td>{_e(RISK_LABEL[item.risk])}</td>"
            f"<td><code>{_e(location)}</code>"
            f"<div class='muted'>{_e(finding.description)}</div>"
            + (f"<div class='muted' style='margin-top:3px'><code>{_e(finding.evidence)}</code></div>"
               if finding.evidence else "")
            + f"</td>"
            f"<td>{_e(item.replacement or '—')}</td>"
            f"<td>{_e(finding.confidence)}</td>"
            f"</tr>"
        )
    more = ""
    if len(assessment.items) > limit:
        more = (f"<p class='muted' style='margin-top:12px'>Showing the top {limit} of "
                f"{len(assessment.items)} findings by priority. The complete inventory is "
                f"in the CycloneDX CBOM.</p>")
    return (
        "<table><thead><tr><th>Priority</th><th>Algorithm</th><th>Quantum status</th>"
        "<th>Where</th><th>Replace with</th><th>Confidence</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>{more}"
    )


def _actions(assessment: Assessment) -> str:
    counts = assessment.by_priority()
    profile = assessment.profile
    actions = []
    if counts["immediate"]:
        actions.append(
            f"<b>Fix {counts['immediate']} classically broken finding"
            f"{'s' if counts['immediate'] != 1 else ''} first.</b> These are exploitable "
            "today and do not depend on any quantum assumption. They are also the easiest "
            "budget to obtain, because the risk is not hypothetical."
        )
    if counts["high"]:
        actions.append(
            f"<b>Schedule {counts['high']} high-priority replacement"
            f"{'s' if counts['high'] != 1 else ''}.</b> These use algorithms that Shor's "
            "algorithm breaks outright. Plan hybrid deployment — classical alongside "
            "post-quantum — rather than a cutover."
        )
    actions.append(
        "<b>Make the inventory continuous.</b> A cryptographic BOM generated once is stale "
        "within a sprint. Run this in CI and fail the build on a new quantum-broken "
        "dependency, the way a software BOM is already handled."
    )
    actions.append(
        "<b>Write crypto-agility into the architecture.</b> The specific algorithm matters "
        "less than whether it can be swapped without a rebuild. Version the algorithm "
        "identifier in every protocol and stored format now."
    )
    actions.append(
        f"<b>Put PQC clauses in procurement.</b> Every contract signed before "
        f"{profile.deadline_year} should require the vendor to state a post-quantum "
        "roadmap and supply a cryptographic bill of materials."
    )
    if profile.is_critical_infrastructure:
        actions.append(
            "<b>Register the programme with the sector regulator.</b> As critical "
            "information infrastructure, evidence of a phased plan will be expected, not "
            "just an end state."
        )
    return "<ul>" + "".join(f"<li>{a}</li>" for a in actions) + "</ul>"


def render(assessment: Assessment, limit: int = 100) -> str:
    profile = assessment.profile
    counts = assessment.by_priority()
    algorithms = assessment.by_algorithm()
    top = "".join(
        f"<tr><td><b>{_e(name)}</b></td><td>{count}</td></tr>"
        for name, count in list(algorithms.items())[:12]
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Quantum readiness — {_e(profile.organisation)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500&display=swap" rel="stylesheet">
<style>{CSS}</style></head><body>
<header><div class="wrap">
  <h1>Post-quantum readiness assessment</h1>
  <p>{_e(profile.organisation)} &middot; {_e(profile.sector)} &middot; {_e(assessment.generated_on)}</p>
</div></header>
<div class="wrap">

  <div class="panel score">
    {_dial(assessment.readiness_score)}
    <div class="body">
      <h3 style="margin-bottom:4px">{_e(assessment.verdict)}</h3>
      <p class="muted" style="margin:0">Scanned <code>{_e(assessment.scanned_path)}</code> and
      classified {len(assessment.items)} cryptographic findings against the NIST
      post-quantum standards.</p>
      <div class="stats">
        <div><b>{counts['immediate']}</b><span>need fixing today</span></div>
        <div><b>{counts['high']}</b><span>high priority</span></div>
        <div><b>{counts['medium'] + counts['low']}</b><span>lower priority</span></div>
        <div><b>{len(algorithms)}</b><span>distinct algorithms</span></div>
      </div>
    </div>
  </div>

  <div class="panel">{_risk_bar(assessment)}</div>

  {_mosca(assessment)}

  <h2>Against the national timeline</h2>
  <div class="panel">{_milestones(assessment)}</div>

  <h2>What to do, in order</h2>
  <div class="panel">{_actions(assessment)}</div>

  <h2>Findings</h2>
  <div class="panel" style="padding:0;overflow-x:auto">{_findings_table(assessment, limit)}</div>

  <h2>Algorithms in use</h2>
  <div class="panel" style="padding:0">
    <table><thead><tr><th>Algorithm</th><th>Occurrences</th></tr></thead>
    <tbody>{top}</tbody></table>
  </div>

  <footer>
    Generated by qsafe. Detection is static and evidence-based; a regex cannot see a
    dynamically selected algorithm, and a clean report is not a guarantee of coverage.
    Treat this as the starting inventory for a manual review, not as its conclusion.
    The assumed arrival year for a cryptographically relevant quantum computer
    ({profile.crqc_year}) is an input, not a prediction.
  </footer>
</div></body></html>"""
