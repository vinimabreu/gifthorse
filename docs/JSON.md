# JSON report

`gifthorse --format json PATH` and `Report.to_dict()` return one object with
the schema id `gifthorse.report/1`. A platform can store it, diff it across
versions, and gate on it. Indicators and evidence are defanged; the only raw
indicator values are in each indicator's `value` field. Member paths and target
names are shown as they are, since they name what was received; the text output
escapes control and direction-changing characters in them.

## Top level

| Key | Type | Meaning |
|---|---|---|
| `schema` | string | `gifthorse.report/1` |
| `targets` | string[] | every path given on the command line, in order, including any that could not be read |
| `unreadable` | string[] | the paths in `targets` that could not be read at all (the run exits 2 unless another path exits 1) |
| `verdict` | string | `BLOCK`, `REVIEW` or `NO FINDINGS` |
| `findings` | object[] | every finding, sorted by target, path, line, rule id |
| `indicators` | object[] | the unique indicators across all findings |
| `coverage` | object | how much was inspected versus present |
| `counts` | object | `{block, review, info}` finding counts |
| `limits` | object | the caps in force for this run; `max_ratio` is still in the object for a stable schema but no longer skips a member, since every read is already bounded by `max_file_bytes` |

The verdict is the highest severity among findings that count; an info finding
never raises it. A report is never `NO FINDINGS` while a member that could hold
executable content was skipped: that case is at least `REVIEW`.

## Finding

| Key | Type | Meaning |
|---|---|---|
| `rule` | string | the rule id, for example `GH201` |
| `title` | string | the rule's short title |
| `severity` | string | `block`, `review` or `info` |
| `target` | string | the command-line target this finding belongs to |
| `path` | string | the location inside the target (`!/` between archive layers, `/` inside a directory, empty for a single file) |
| `line` | integer | the line, or `0` when the finding is about a name |
| `message` | string | one sentence on what it does |
| `evidence` | string | a short snippet, defanged, with control and direction-changing characters escaped |
| `trigger` | string | the everyday action that would set the rule off |
| `next_step` | string | what to do instead |
| `indicators` | object[] | indicators found in this finding |

`target` plus `path` plus `:line` is the location the text output prints, for
example `brief.zip!/Project Requirements and Budget.vbs:1`.

## Indicator

| Key | Type | Meaning |
|---|---|---|
| `kind` | string | `url`, `host`, `ipv4`, `ipv6`, `sha256` or `wallet` |
| `value` | string | the raw value, for an abuse report |
| `defanged` | string | the inert form, which the text output and the `--iocs` block show |

## Coverage

| Key | Type | Meaning |
|---|---|---|
| `present` | integer | file entries present in the target |
| `inspected` | integer | entries whose content was read and examined |
| `skipped` | object[] | each skipped entry as `{path, reason, executable_capable}` |

A skip reason is one of: `encrypted`, `unreadable format`, `unreadable file`,
`unreadable folder`, `not a regular file` (a FIFO, socket or device),
`symlink not followed` (every link: no link is followed), `rar content not
inspectable (names only)`, `dependency folder not
scanned` (a `node_modules`, a virtualenv or a `__pycache__` a folder walk did
not enter), `git object store not scanned` (a `.git/objects`, `lfs` or `logs`
folder), or a `cap: ...` reason. A skip inside a nested archive carries the
full path, for example `tests/data/case.npz!/matrix.npy`. A skip of a whole
archive, of what follows a broken header, or of the entries past the entry
limit is recorded under a name in angle brackets after the archive's own path:
`<zip archive>` for the target itself, `assets/data.bin!/<zip archive>` for a
nested one, `<rest of tar archive>` or `<rest of rar archive>` for a partial
read, and `<N entries past the entry limit>` for the content not read past the
entry cap.

`executable_capable` denies by default: a skip counts as one that could have
held code unless its reason is on a short list. The only non-capable reason
is `git object store not scanned`. The caps
on bytes and the RAR names-only skip are judged by the skipped file's type: a
type no content rule reads, whose name is not an executable, script or archive,
cannot have produced a finding (C source over the size cap, an image, a NumPy
array). Everything else counts: an encrypted or unreadable member, a FIFO or
device, an unreadable folder, any link, entries past the entry limit, a
compressed file of more streams than the stream limit. Only a capable skip keeps the verdict at
REVIEW or above, and every capable skip produces a finding (GH104, GH105 or
GH109).

## Example

Abridged: the GH101 finding of the same run is left out, so `counts` shows two
block findings while only one is listed.

```json
{
  "schema": "gifthorse.report/1",
  "targets": ["brief.zip"],
  "unreadable": [],
  "verdict": "BLOCK",
  "findings": [
    {
      "rule": "GH201",
      "title": "Download, write and run chain in a Windows script",
      "severity": "block",
      "target": "brief.zip",
      "path": "!/Project Requirements and Budget.vbs",
      "line": 1,
      "message": "The script downloads a file, saves it, then runs it.",
      "evidence": "download line 1, write line 4, run line 6",
      "trigger": "when you double-click the script on Windows",
      "next_step": "report it; use the --iocs block for the hosts it would contact",
      "indicators": [
        {
          "kind": "url",
          "value": "http://stage.cdn.example.invalid/payload",
          "defanged": "hxxp[://]stage[.]cdn[.]example[.]invalid/payload"
        }
      ]
    }
  ],
  "indicators": [
    {
      "kind": "url",
      "value": "http://stage.cdn.example.invalid/payload",
      "defanged": "hxxp[://]stage[.]cdn[.]example[.]invalid/payload"
    }
  ],
  "coverage": {"present": 3, "inspected": 3, "skipped": []},
  "counts": {"block": 2, "review": 0, "info": 0},
  "limits": {"max_entries": 10000, "max_total_bytes": 268435456, "max_file_bytes": 8388608, "max_depth": 3, "max_ratio": 100, "max_line": 4096}
}
```
