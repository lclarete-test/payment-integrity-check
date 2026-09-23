import json
import tempfile
import unittest
from pathlib import Path

from payment_integrity_check.analyzer import analyze_text, scan, scan_report
from payment_integrity_check.cli import main, render_html, render_sarif, render_text


class AnalyzerTests(unittest.TestCase):
    def test_charge_before_local_insert_with_forwarded_kwargs(self):
        source = """import stripe
class ChargeQuerySet:
    def create(self, **kwargs):
        charge = stripe.Charge.create(amount=100, **kwargs)
        return super().create(stripe_id=charge.id)
"""
        findings = analyze_text(source, "payments.py")
        self.assertEqual([f.rule_id for f in findings], ["PAY001", "PAY002"])
        self.assertEqual([f.line for f in findings], [4, 4])
        self.assertIn("**kwargs may supply one", findings[1].evidence)

    def test_aliased_import_payment_intent(self):
        source = """from stripe import PaymentIntent as PI
def pay(key):
    intent = PI.create(amount=500, currency='usd', idempotency_key=key)
    order.save()
"""
        findings = analyze_text(source)
        self.assertEqual([f.rule_id for f in findings], ["PAY001"])
        self.assertIn("orphan PaymentIntent", findings[0].impact)

    def test_no_finding_when_local_operation_precedes_payment_and_key_explicit(self):
        source = """import stripe as s
def pay(order):
    operation = PaymentOperation.objects.create(order=order)
    return s.PaymentIntent.create(amount=500, idempotency_key=operation.key)
"""
        self.assertEqual(analyze_text(source), [])

    def test_webhook_without_event_id_reference(self):
        source = """import stripe
def webhook(payload, signature):
    event = stripe.Webhook.construct_event(payload, signature, 'test-secret')
    order.save()
"""
        self.assertEqual([f.rule_id for f in analyze_text(source)], ["PAY003"])
        self.assertEqual(analyze_text(source.replace("order.save()", "seen = event['id']\n    order.save()")), [])

    def test_nested_function_is_not_attributed_to_outer_function(self):
        source = """import stripe
def outer():
    def inner():
        stripe.Charge.create(amount=100)
    order.save()
"""
        self.assertEqual([f.rule_id for f in analyze_text(source)], ["PAY002"])

    def test_html_escapes_content_and_sarif_locations(self):
        findings = analyze_text("import stripe\ndef pay():\n    stripe.Charge.create(amount=1)\n", "<unsafe>.py")
        self.assertIn("&lt;unsafe&gt;.py", render_html(findings))
        self.assertIn("https://github.com/example/repo/blob/abc/%3Cunsafe%3E.py#L3",
                      render_html(findings, source_url="https://github.com/example/repo/blob/abc"))
        sarif = json.loads(render_sarif(findings))
        self.assertEqual(sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 3)

    def test_report_explains_all_checks_and_counts_locations_separately(self):
        findings = analyze_text("""import stripe
def pay():
    charge = stripe.Charge.create(amount=100)
    order.save()
""", "payments.py")
        report = render_text(findings, ["legacy.py: cannot parse"], 2)
        self.assertIn("Ran 3 checks across 2 Python file(s)", report)
        self.assertIn("2 check(s) matched at 1 code location(s), producing 2 observation(s)", report)
        self.assertIn("PAY003 — Repeated webhook delivery: no matching pattern observed", report)
        self.assertIn("What remains uncertain:", report)
        self.assertIn("legacy.py: cannot parse", report)
        html_report = render_html(findings, ["legacy.py: cannot parse"], 2)
        self.assertIn("<h3>Why it matters</h3>", html_report)
        self.assertIn("No matching pattern observed", html_report)
        self.assertIn("Files skipped:", html_report)

    def test_cli_scans_local_files_without_running_them(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "executed"
            (root / "payment.py").write_text(
                f"import stripe\nopen({str(marker)!r}, 'w').write('bad')\n"
                "def pay():\n    stripe.Charge.create(amount=1)\n",
                encoding="utf-8",
            )
            report = root / "report.json"
            self.assertEqual(main(["scan", str(root), "--format", "json", "--output", str(report)]), 0)
            self.assertFalse(marker.exists())
            self.assertEqual(json.loads(report.read_text())["findings"][0]["rule_id"], "PAY002")

    def test_ignores_virtual_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            nested = Path(directory) / ".venv"
            nested.mkdir()
            (nested / "test.py").write_text("import stripe\ndef pay():\n    stripe.Charge.create(amount=1)\n")
            self.assertEqual(scan(directory), [])

    def test_legacy_stripe_wrapper_and_python2_skip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "models.py").write_text("import stripe\nclass StripeAPIMixin:\n    _stripe = stripe\n")
            (root / "querysets.py").write_text("""class ChargeQuerySet:
    def create(self, customer, account, **kwargs):
        if customer:
            charge = customer.api().charges().create(amount=10, **kwargs)
            return super(ChargeQuerySet, self).create(stripe_id=charge.id)
        elif account:
            charge = self.model._stripe.Charge.create(amount=10, **kwargs)
            return super(ChargeQuerySet, self).create(stripe_id=charge.id)
""")
            (root / "version.py").write_text("print 'old syntax'\n")
            report = scan_report(root)
            self.assertEqual(len(report.findings), 4)
            self.assertEqual([f.rule_id for f in report.findings], ["PAY001", "PAY002", "PAY001", "PAY002"])
            self.assertEqual(report.files_analyzed, 2)
            self.assertEqual(len(report.skipped), 1)


if __name__ == "__main__":
    unittest.main()
