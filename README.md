# qsafe

Cryptographic inventory and post-quantum readiness assessment.

India's DST task force, under the National Quantum Mission, has set deadlines:
cryptographic inventories complete across critical information infrastructure by
December 2027, high-priority systems migrated by December 2028, full adoption by
December 2029. A cryptographic bill of materials is recommended as mandatory in
government RFPs.

Nobody can migrate cryptography they cannot find. `qsafe` finds it, ranks it by
what actually needs replacing first, and emits a CycloneDX CBOM a procuring
authority can diff between releases.

It is aimed at the institutions that will not be served by the large consulting
firms: cooperative and regional rural banks, district hospitals, state utilities,
university systems — organisations holding data with a long confidentiality
horizon, no CISO, and a deadline they mostly do not know exists.

## Install

```bash
pip install -r requirements.txt
```

The only hard dependency is `cryptography`, which is used to parse real
certificates and keys rather than guess at them from filenames.

## Use

```bash
python -m qsafe.cli /path/to/estate \
  --org "Sample Cooperative Bank" \
  --sector banking \
  --data-lifetime 25 \
  --migration-years 4 \
  --critical-infrastructure
```

Three artefacts land in `qsafe-output/`:

| File | What it is |
|---|---|
| `readiness-report.html` | The assessment. Open in a browser; print to PDF for the board pack. |
| `cbom.json` | CycloneDX 1.6 cryptographic bill of materials. Machine-readable, diffable. |
| `findings.json` | Every finding with its risk classification, for your own tooling. |

Try it against the worked example first. The sample certificates are generated
locally rather than committed — a repository about cryptographic hygiene should
not ship a private key, even a throwaway one:

```bash
python samples/generate_certs.py
python -m qsafe.cli samples/legacy-bank --org "Sample Cooperative Bank" \
  --sector banking --data-lifetime 25 --migration-years 4 --critical-infrastructure
```

On the sample estate this returns a readiness score of 28 out of 100 and 23
findings: an RSA-1024 certificate, MD5 and SHA-1 in application code, 3DES in
both a Java cipher and an nginx cipher list, and an unencrypted private key
sitting in the certificate directory.

## How findings are ranked

Two questions decide the order, and the first one dominates.

**Is it broken today?** MD5, SHA-1, 3DES, RC4, RSA below 2048 bits. These are
exploitable now, have nothing to do with quantum, and are the easiest budget to
obtain because the risk is not hypothetical. They sort above everything.

**Is it broken by quantum?** RSA, ECDSA, ECDH, Ed25519, X25519, DH, DSA are
broken outright by Shor's algorithm — key size does not help, and these must be
replaced rather than strengthened. AES-128 and SHA-256 are weakened by Grover's
algorithm, which halves effective strength, and are strengthened rather than
replaced. AES-256, ChaCha20, HMAC and the NIST post-quantum standards are sound.

Within a band, findings are scored by confidence. A parsed certificate is
`certain`; a regex match on a commented-out line is `low`.

## Mosca's inequality

The report is built around it:

> If **X** (how long the data must stay confidential) plus **Y** (how long
> migration will take) exceeds **Z** (years until a cryptographically relevant
> quantum computer exists), then data encrypted today is already exposed.

This is the Harvest Now, Decrypt Later problem, and it is why "we will deal with
it when quantum computers arrive" is not a position — an adversary recording
traffic today decrypts it later.

`Z` is unknowable. `qsafe` takes it as an explicit input (`--crqc-year`, default
2035) so the assumption can be argued with in the room rather than buried in a
scoring function. Move it and watch the verdict change; that sensitivity is the
point.

## In CI

Treat cryptography the way software bills of materials are already treated. Fail
the build when someone introduces a newly broken primitive:

```yaml
- name: Cryptographic inventory
  run: |
    pip install -r requirements.txt
    python -m qsafe.cli . -o qsafe-output --fail-on immediate
- uses: actions/upload-artifact@v4
  with:
    name: cbom
    path: qsafe-output/cbom.json
```

`--fail-on` accepts `immediate`, `high`, `medium`, `low`, or `never`. Start at
`immediate` so the gate is credible, then tighten. Exit codes: `0` clean, `1`
threshold breached, `2` bad path.

## What it detects

Python, Java, JavaScript and Go call sites for key generation, signing and
hashing. TLS cipher suites in nginx, Apache and application configuration. SSH
host and user keys. JWT signing algorithms. And, by actually parsing them rather
than pattern-matching: X.509 certificates (public key algorithm, key size,
signature hash, subject, expiry) and unencrypted private keys left on disk.

It also detects post-quantum algorithms already in place, including the
pre-standard Kyber and Dilithium names — worth flagging, because an
implementation tracking a round-three draft is not FIPS 203 or 204 compliant.

## Honest limits

**Static detection only.** A regex cannot see an algorithm selected at runtime
from configuration, chosen by a library default, or buried in a compiled binary
or a vendor appliance. A clean report is not a guarantee of coverage; it is the
starting point for a manual review.

**Rule coverage is partial.** Roughly fifty rules across four languages. A COBOL
core banking system, a mainframe, or an embedded HSM configuration will return
nothing useful. Those estates need interviews, not scanners — and they are
exactly where the worst findings live.

**Vendor and dependency cryptography is out of scope.** What your libraries do
internally is invisible here. Pair this with a software BOM and vendor
attestations.

**The confidence scores are heuristics**, not measurements. `low` means a human
should look, not that it is probably fine.

**The CRQC year is an assumption, not a forecast.** Nobody knows. The default of
2035 is neither the most aggressive nor the most conservative estimate in
circulation.

## Tests

```bash
python -m pytest -q     # 25 tests
```

Covering the algorithm catalogue, scanner behaviour across languages and file
types, real certificate parsing, the Mosca calculation, prioritisation ordering,
CycloneDX structure, HTML escaping, and the CLI exit codes.

## Layout

```
qsafe/algorithms.py   Quantum risk classification per primitive, with rationale
qsafe/rules.py        Detection rule pack
qsafe/scanner.py      Tree walk, textual rules, certificate and key parsing
qsafe/risk.py         Mosca's inequality, prioritisation, DST milestone mapping
qsafe/cbom.py         CycloneDX 1.6 emitter
qsafe/report.py       HTML readiness report
qsafe/cli.py          Command line interface
samples/legacy-bank/  A worked example with deliberately weak cryptography
samples/generate_certs.py  Generates the sample certificates locally
```

## Licence and intent

MIT. Use it, fork it, bill for it. It exists because the institutions that most need a
cryptographic inventory are the least likely to be sold one.
