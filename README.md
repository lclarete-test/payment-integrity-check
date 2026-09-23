# Payment Integrity Check

**Payment Integrity Check** is a local Python library and CLI that reviews
payment code for patterns that can leave a processor and an application's
database out of sync. It uses deterministic rules and fixed report templates.
It does not use AI, execute the code under review, or connect to a payment
processor.

The initial release understands selected Stripe patterns in Python. The
problem and report format are processor independent; adding support for other
processors requires explicit detection rules and tests.

## The problem

A payment request and a database write cannot usually be committed as one
transaction. A processor can accept an operation while the local write fails.
If the application retries without linking the attempt to the same business
operation, it may create another payment or lose track of the first one.
Webhook events can also arrive more than once. A repeated event can change
local state twice when the handler is not idempotent.

These are *failure scenarios to investigate*. Finding a code pattern does not
show that an incident occurred, that a customer was charged twice, or that a
security vulnerability exists.

## Installation

Requires Python 3.10 or newer. Install from a clone of this repository:

```bash
python -m pip install .
```

## Run a scan

```bash
payment-integrity-check scan path/to/project
payment-integrity-check scan path/to/project --format html --output report.html
payment-integrity-check scan path/to/project --format json --output findings.json
payment-integrity-check scan path/to/project --format sarif --output findings.sarif
```

For clickable links to GitHub lines in the HTML report, pass a commit-pinned
URL for the analyzed repository:

```bash
payment-integrity-check scan path/to/project --format html --output report.html \
  --source-url https://github.com/owner/repo/blob/COMMIT_SHA
```

Run the included synthetic example after installation:

```bash
payment-integrity-check scan examples/demo.py --format html --output report.html
```

The Python API is `from payment_integrity_check import scan`.

## What the report says

Every HTML or text report starts with a count of checks run, categories with
matches, distinct code locations, and total observations. These counts differ
when two checks match the same payment call. It then shows **all three checks**:

| Rule | Looks for | Question to investigate |
| --- | --- | --- |
| `PAY001` | A payment operation appears before a local write | Could a successful provider operation lack a corresponding local record? |
| `PAY002` | A payment call has no explicit `idempotency_key` | Does the same business operation reuse a stable key across retries? |
| `PAY003` | A Stripe webhook handler writes locally without visibly reading `event.id` | Can repeated delivery apply the state change twice? |

For each match, the report explains why the pattern matters, shows its exact
file and line, describes a *conditional* impact, proposes a test and possible
fix, and names what static analysis cannot establish. A rule without matches
is labeled **No matching pattern observed**, never **Passed**. The report also
lists files it could not parse, including some older Python 2 files.
If a project has no analyzable Python files, the report says **not applicable**
and the CLI exits with status `3`; it does not imply that the rules passed.

The English wording lives in
[`payment_integrity_check/report_templates.py`](payment_integrity_check/report_templates.py).
See [`REPORT_TEMPLATE.md`](REPORT_TEMPLATE.md) for the template structure.
The output is suitable for engineering review; it is not an automated audit
certificate.

## How it works

The scanner reads local `.py` files and parses them with Python's standard
`ast` module. It recognizes selected Stripe imports and aliases, common ORM
writes, and a few legacy Stripe wrapper patterns. It inspects source order and
call signatures and renders fixed explanations. It does not import or run
the target project. Source code is not uploaded by the scanner.

Static analysis has limits: other modules, branches, wrappers, database
constraints, and retry policies may change the real behavior. An explicit
idempotency key does not prove the key is stable. A visible event ID does not
prove durable webhook deduplication. Unrecognized calls and processors are
outside this initial release. Findings are therefore prompts to reproduce a
failure with test credentials and synthetic data.

## Development

```bash
python -m unittest discover -s tests -v
```

The package has no runtime dependencies. Pull requests that add provider
support should include both a failing example and a safe example so the rule
can be checked for false positives.

## License

MIT. See [LICENSE](LICENSE).
