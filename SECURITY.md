# Security policy

`gifthorse` is a security tool, so the bugs that matter most are the ones that
let a hostile input slip past it or turn the scanner itself into a target.

## What to report privately

Report these through GitHub's private vulnerability reporting (the Security tab,
"Report a vulnerability"), not a public issue:

- A **bypass**: a package the tool should flag that comes back NO FINDINGS.
- A **false negative** in a specific rule.
- Any way to make the scanner **execute, write, fetch, or hang** on a crafted
  input, which would break a stated guarantee.

Please include a builder that assembles the shape in memory, as the tests do.
Do not attach a real malware sample.

## What belongs in a public issue

A false positive (a benign package flagged) and usage questions are not
sensitive; open a normal issue with the templates provided.

## Scope and expectations

Static analysis is evadable by design. NO FINDINGS means nothing obvious was
found, not that the input is safe. A report that the tool "missed" a sample
that is only detectable by running it is expected behavior, not a vulnerability.
