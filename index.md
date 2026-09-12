---
layout: default
title: qsafe
description: Find out what cryptography your organisation uses, and what has to be replaced before India's post-quantum deadlines.
---

# Your encryption has an expiry date

India has set national deadlines for replacing it.

The Department of Science and Technology's task force, under the National
Quantum Mission, published the timeline: **a complete inventory of the
cryptography you use by December 2027**, migration of high-priority systems by
December 2028, and full adoption of post-quantum algorithms by December 2029.
A cryptographic bill of materials is recommended as mandatory in government
procurement.

The inventory is the deadline that matters, because nothing else can start until
it is done. And it is slow work: identifying every place cryptography is used
across an estate built over two decades takes months, not weeks.

**qsafe** produces that inventory, free.

[**See a sample report**](sample-report.html) &nbsp;·&nbsp;
[**Get the code**](https://github.com/duttsiddharth/qsafe)

---

## Why this is urgent rather than theoretical

The usual objection is reasonable: quantum computers that can break encryption
do not exist yet, so why act now?

Because of what security people call **harvest now, decrypt later**. An
adversary does not need a quantum computer today. They need only to record your
encrypted traffic today and store it until they have one. Anything with a long
confidentiality life — customer records, medical files, loan documents,
examination records — is being harvested on that assumption.

The arithmetic is known as **Mosca's inequality**:

> If the years your data must stay confidential, plus the years your migration
> will take, exceed the years before a quantum computer can break today's
> encryption, then what you encrypt today is already exposed.

For a bank holding customer records for 25 years, with a realistic 4-year
migration, against a commonly assumed arrival around 2035 — that is 29 years of
exposure against 9 years of warning. Breached by twenty years, today.

You can disagree with the arrival date. That is the point: qsafe takes it as an
input you set, so it is an assumption you can argue about in a meeting rather
than a number buried in a vendor's scoring model.

---

## What you get

A written assessment naming what cryptography your systems use, what has to be
replaced, in what order, and against which deadline — plus a machine-readable
cryptographic bill of materials in the CycloneDX format a procuring authority or
auditor can check.

[**Look at a sample report**](sample-report.html) for a fictional cooperative
bank. It scores 28 out of 100 across 23 findings.

---

## What usually turns up first

Not the quantum problems. The ones already broken.

MD5, SHA-1, Triple DES, RSA keys below 2048 bits. These are exploitable **today**,
have nothing to do with quantum computing, and are far easier to get budget for
because the risk is not hypothetical. Most organisations that run a quantum
readiness assessment discover it was really an audit of cryptographic debt they
already had.

That is a good outcome, not a disappointing one.

---

## Who this is built for

Cooperative banks, regional rural banks, district hospitals, state utilities,
university systems, and smaller public sector institutions.

Large private banks will engage a global consultancy and be fine. The
institutions above generally will not — they hold data with a long
confidentiality horizon, often have no dedicated security officer, and in most
cases have not heard that a deadline exists. Commercial inventory tooling is
priced for large enterprises.

That gap is the reason this is free and MIT licensed.

---

## What it cannot do

It reads source code, configuration files, certificates and keys. It does not
read a COBOL core banking system, a mainframe, a vendor appliance, or anything
compiled. Those estates need interviews and vendor attestations, not a scanner —
and they are usually where the most serious findings sit.

Treat the report as the start of a review, not its conclusion. A clean result is
not a guarantee of coverage.

---

## Using it

If you have a technical team, the tool runs on your own infrastructure and
nothing leaves your control. Instructions and source are on
[GitHub](https://github.com/duttsiddharth/qsafe).

If you do not, or you would like the assessment written up properly, get in
touch.

**Siddharth Dutt** — Founder and Principal Consultant, SD Advisory
[sdutt@sdadvisory.in](mailto:sdutt@sdadvisory.in) · +91 96111 05276 ·
[sdadvisory.in](https://sdadvisory.in)


Twenty years in enterprise technology across BFSI and telecom, including service
delivery management for Standard Chartered, Citibank, UOB and Manulife.
