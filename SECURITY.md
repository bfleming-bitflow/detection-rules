# Security policy

## Scope

This repository contains detection rules, synthetic fixtures and a small Python test harness. It
does not run as a service and handles no credentials or production telemetry.

Reports are welcome for:

- defects in a rule that cause it to miss its documented behaviour or to match clearly benign
  fixtures that are already in the repository;
- vulnerabilities in the tooling or CI workflow.

Reports about third-party products (operating systems, applications, logging pipelines) should go
to the vendor.

## Reporting

Use GitHub private vulnerability reporting ("Report a vulnerability" under the Security tab).
Include the rule identifier, the fixture or event that demonstrates the problem, and any public
references that support the correction.

Rule quality issues that are not security defects can be filed as regular issues.

## Response

Reports are acknowledged within five business days. Confirmed issues are fixed in the next
release and recorded in `CHANGELOG.md`, with credit if the reporter wishes.

## Handling of fixtures

Fixtures under `tests/fixtures/` are synthetic. They use reserved documentation names
(`example.invalid`) and documentation address ranges (`192.0.2.0/24`). Do not replace them with
samples taken from incidents.
