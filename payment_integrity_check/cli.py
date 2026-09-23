"""Command-line interface and deterministic reports."""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from urllib.parse import quote

from .analyzer import Finding, scan_report
from .report_templates import RULE_TEMPLATES


def _by_rule(findings: list[Finding]) -> dict[str, list[Finding]]:
    return {rule.id: [f for f in findings if f.rule_id == rule.id] for rule in RULE_TEMPLATES}


def _summary(findings: list[Finding], files_analyzed: int | None) -> str:
    categories = len({f.rule_id for f in findings})
    sites = len({(f.path, f.line) for f in findings})
    files = f" across {files_analyzed} Python file(s)" if files_analyzed is not None else ""
    return (f"Ran {len(RULE_TEMPLATES)} checks{files}. "
            f"{categories} check(s) matched at {sites} code location(s), producing {len(findings)} observation(s).")


def render_text(findings: list[Finding], skipped: list[str] | None = None, files_analyzed: int | None = None) -> str:
    lines = ["PAYMENT INTEGRITY REVIEW", _summary(findings, files_analyzed),
             "A match is a code review prompt, not a confirmed incident or vulnerability.", ""]
    if skipped:
        lines.extend(["Coverage limits:", *(f"  - {item}" for item in skipped), ""])
    for rule in RULE_TEMPLATES:
        matches = _by_rule(findings)[rule.id]
        lines.extend([f"{rule.id} — {rule.title}: {len(matches)} match(es)" if matches else
                      f"{rule.id} — {rule.title}: no matching pattern observed",
                      f"  Question: {rule.question}"])
        if matches:
            lines.extend([f"  What this means: {rule.why}", "  What the code shows:"])
            lines.extend(f"    - {f.path}:{f.line}: {f.evidence}" for f in matches)
            lines.extend([f"  Possible impact: {matches[0].impact}",
                          f"  How to verify: {matches[0].check}",
                          f"  Proposed fix: {matches[0].fix}",
                          f"  What remains uncertain: {rule.limits}"])
        else:
            lines.append("  Interpretation: This pattern was not observed in analyzed files; it does not establish that the flow is safe or that no such handler exists.")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_html(findings: list[Finding], skipped: list[str] | None = None,
                files_analyzed: int | None = None, source_url: str | None = None) -> str:
    escape = html.escape
    cards = []
    grouped = _by_rule(findings)
    for rule in RULE_TEMPLATES:
        matches = grouped[rule.id]
        heading = f"<h2>{escape(rule.id)} · {escape(rule.title)}</h2>"
        status = (f"<span class=\"tag\">{len(matches)} match(es)</span>" if matches else
                  "<span class=\"tag quiet\">No matching pattern observed</span>")
        question = f"<p class=\"question\">{escape(rule.question)}</p>"
        if matches:
            locations = []
            for f in matches:
                location = escape(f"{f.path}:{f.line}")
                if source_url:
                    url = source_url.rstrip("/") + "/" + quote(f.path, safe="/") + f"#L{f.line}"
                    location = '<a href="' + escape(url, quote=True) + '">' + location + '</a>'
                locations.append("<li><strong>" + location + "</strong> — " + escape(f.evidence) + "</li>")
            body = ("<h3>Why it matters</h3><p>" + escape(rule.why) + "</p>"
                    + "<h3>What the code shows</h3><ul>" + "".join(locations) + "</ul>"
                    + "<h3>Possible impact</h3><p>" + escape(matches[0].impact) + "</p>"
                    + "<h3>How to verify</h3><p>" + escape(matches[0].check) + "</p>"
                    + "<h3>Proposed fix</h3><p>" + escape(matches[0].fix) + "</p>"
                    + "<h3>What remains uncertain</h3><p>" + escape(rule.limits) + "</p>")
        else:
            body = ("<p>This pattern was not observed in analyzed files. That does not establish that the flow "
                    "is safe or that no such handler exists.</p>")
        cards.append("<article>" + heading + status + question + body + "</article>")
    coverage = ("<section class=\"coverage\"><h2>Coverage and limits</h2>"
                + (f"<p>{files_analyzed} Python file(s) parsed.</p>" if files_analyzed is not None else "")
                + ("<p><strong>Files skipped:</strong> " + "; ".join(escape(s) for s in skipped) + "</p>" if skipped else "")
                + "<p>The analyzer reads code locally and does not execute payment requests. "
                  "It cannot establish production impact or prove the absence of other risks.</p></section>")
    return ("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>Payment integrity review</title><style>"
            "body{font:15px/1.6 system-ui,sans-serif;max-width:900px;margin:3rem auto;padding:0 1.4rem;color:#17253c;background:#fafcfd}"
            "h1{font-size:2.1rem;line-height:1.2;margin:.25rem 0}h2{font-size:1.2rem;margin:0 0 .5rem}h3{font-size:.88rem;margin:1.25rem 0 .15rem;text-transform:uppercase;letter-spacing:.035em;color:#526477}"
            "p{margin:.3rem 0 .8rem}li{margin:.45rem 0}.eyebrow{font-size:.75rem;font-weight:700;letter-spacing:.1em;color:#087e83}"
            "article,.coverage{border:1px solid #d2dfe4;border-radius:10px;padding:1.3rem 1.6rem;margin:1.1rem 0;background:white}"
            ".summary{font-size:1.05rem;margin:1rem 0}.question{font-weight:650}.tag{display:inline-block;background:#e0f3f1;color:#12615e;border-radius:4px;padding:.2rem .55rem;font-size:.78rem;font-weight:700}"
            ".quiet{background:#ebeff2;color:#536371}a{color:#087e83}small{color:#516372}"
            "@media print{body{background:white;margin:.5rem auto}article,.coverage{break-inside:avoid}}</style>"
            "<main><div class=\"eyebrow\">DETERMINISTIC CODE REVIEW · NO AI</div><h1>Payment integrity review</h1>"
            "<p class=\"summary\">" + escape(_summary(findings, files_analyzed)) + "</p>"
            "<p>A match is a code review prompt, not a confirmed incident or vulnerability.</p>"
            + "".join(cards) + coverage + "<small>Template-based local analysis · No target code was executed.</small></main></html>\n")


def render_sarif(findings: list[Finding]) -> str:
    rules = {f.rule_id: {"id": f.rule_id, "name": f.title, "shortDescription": {"text": f.title}}
             for f in findings}
    results = [{
        "ruleId": f.rule_id,
        "level": "note",
        "message": {"text": f.evidence + " Possible impact: " + f.impact + " How to check: " + f.check},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": f.line, "endLine": max(f.line, f.end_line)},
        }}],
        "partialFingerprints": {"primaryLocationLineHash": f"{f.rule_id}:{f.path}:{f.line}"},
    } for f in findings]
    return json.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                       "runs": [{"tool": {"driver": {"name": "payment-integrity-check", "version": "0.1.0",
                                                     "rules": list(rules.values())}}, "results": results}]}, indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="payment-integrity-check", description="Local Python payment integrity review")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_parser = sub.add_parser("scan", help="Analyze a .py file or directory")
    scan_parser.add_argument("path", nargs="?", default=".")
    scan_parser.add_argument("--format", choices=["text", "json", "html", "sarif"], default="text")
    scan_parser.add_argument("--output", type=Path, help="Write report to a file (default: stdout)")
    scan_parser.add_argument("--source-url", help="Commit-pinned HTTPS URL of source tree for clickable HTML locations")
    args = parser.parse_args(argv)
    try:
        if args.source_url and not args.source_url.startswith("https://"):
            raise ValueError("--source-url must be an HTTPS URL")
        report = scan_report(args.path)
        findings = report.findings
        content = {"text": render_text, "html": render_html, "sarif": render_sarif,
                   "json": lambda fs: json.dumps({"findings": [f.to_dict() for f in fs],
                                                  "checks": [{"id": rule.id, "title": rule.title,
                                                              "matches": sum(f.rule_id == rule.id for f in fs)}
                                                             for rule in RULE_TEMPLATES],
                                                  "files_analyzed": report.files_analyzed,
                                                  "skipped": report.skipped}, indent=2) + "\n"}
        if args.format == "html":
            output = render_html(findings, report.skipped, report.files_analyzed, args.source_url)
        elif args.format == "text":
            output = content[args.format](findings, report.skipped, report.files_analyzed)
        else:
            output = content[args.format](findings)
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
        return 0
    except (OSError, ValueError) as exc:
        print(f"payment-integrity-check: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
