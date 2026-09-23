# How the report is built

The report uses fixed text in `payment_integrity_check/report_templates.py`. No
LLM or external service writes its explanations. Each rule defines:

1. **Question**: what the check tries to find.
2. **Why it matters**: the failure mechanism, stated conditionally.
3. **What the code shows**: file, line and evidence produced by the analyzer.
4. **Possible impact**: the consequence if the failure scenario occurs.
5. **How to verify**: a test an engineer can run with test data.
6. **Proposed fix**: an engineering response to review, not an automated edit.
7. **What remains uncertain**: limits of static analysis and alternate controls.

All three checks appear in every HTML and text report. A check without matches
is labeled **No matching pattern observed**, never **Passed**. The summary
counts matching categories, distinct source locations, and observations
separately: two checks at one location are two observations about one call
site. The coverage section names any files that could not be parsed.

To change the wording, edit the corresponding `RuleTemplate` and keep the
uncertainty statement. To add a rule, add its detection in `analyzer.py`,
its template in `report_templates.py`, and positive and negative tests.

Example opening for a hypothetical run with two checks matching at one location:

> Ran 3 checks across 12 Python files. 2 checks matched at 1 code location,
> producing 2 observations. A match is a code review prompt, not a confirmed
> incident or vulnerability.

The CLI generates the HTML report with:

```bash
payment-integrity-check scan path/to/repo --format html --output report.html
```
