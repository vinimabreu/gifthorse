# Contributing

Thanks for helping. The bar is high because this is a tool people trust to tell
them whether to open a stranger's file.

## Setup

```text
pip install -e ".[dev]"
pytest
ruff check .
mypy
```

The suite runs offline with no key. If anything needs the network to pass, that
is a bug in the test.

## Adding a rule

A rule is four things, in one change:

1. **A registry entry** in `src/gifthorse/registry.py`: a stable id (next free
   number in its family, never reused), a title, a family, a default severity,
   and the `means`, `why`, `trigger` and `next_step` text. The `trigger` and
   `next_step` are written for a reader with no security background. Regenerate
   the docs with `python -c "from gifthorse import report; open('docs/RULES.md','w').write(report.render_rules_markdown())"`.
2. **The check** in `src/gifthorse/rules.py`, scoped to the file kinds it
   applies to. Scope is not optional: a rule that fires on prose or on test
   fixtures will flag this repository's own scan and fail CI. That self-scan is
   the main defense against a noisy rule.
3. **A positive and a negative test** in `tests/test_rules.py`. No rule ships
   without both.
4. **A fixture builder** in `tests/builders.py` that assembles the shape in
   memory from fragments. The dangerous token must not sit whole in the source
   of a committed file, and **no real malware sample ever enters the repository.**

After adding or changing a rule, run `PYTHONPATH=src python tools/mutation_check.py`: it turns each rule off in turn (through a test-only seam) and fails if any rule's removal goes unnoticed by the suite. A rule that reads more files, or reads them differently, also gets a run of the false-positive benchmark in `benchmark/` (see its README): a new BLOCK on a popular package is a bug to fix before merging, and a new REVIEW needs a reason in the pull request.

To try the command line from a checkout, use `python -P -m gifthorse PATH`; plain `python -m` is refused on purpose.

## Rules of the house

- The scanner never executes, imports, evaluates, extracts, writes, or reaches
  the network. The guarantee tests enforce this; do not weaken them.
- Patterns run on length-capped segments and must stay linear on hostile input.
  Compile every pattern at module level: the regex-safety test walks each module
  in the package, collects every compiled pattern (loose or inside a tuple of
  rules), and times it on a megabyte of pathological text (single characters,
  newline-heavy text, and each pattern's own opening token repeated), failing a
  pattern whose time grows faster than the input. A companion test counts the
  `re.compile` calls in the source and fails if any pattern is compiled inline
  where the safety test cannot reach it.
- Keep writing plain. No em dashes, no filler.

## Reporting a bypass

A package the tool should flag but misses is a security issue; report it
privately per [SECURITY.md](SECURITY.md), not as a public issue.
