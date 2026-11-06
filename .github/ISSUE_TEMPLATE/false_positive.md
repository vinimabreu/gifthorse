---
name: False positive
about: A benign package was flagged REVIEW or BLOCK
title: "False positive: "
labels: false-positive
---

**Which rule fired**

The rule id from the output, for example GH101.

**What the package actually is**

A plain description of the benign file, folder or archive, and why the finding
is wrong.

**How to reproduce the shape**

A small builder that assembles the shape in memory, as the tests do, or a
public link to the kind of project it came from. Do not attach anything you do
not trust.

**Output**

The relevant lines of `gifthorse` output, or the JSON finding.

**Version**

`gifthorse --version` and your Python version.
