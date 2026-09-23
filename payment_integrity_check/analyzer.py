"""Conservative AST checks. This module never imports or executes target code."""

from __future__ import annotations

import ast
import warnings
from dataclasses import asdict, dataclass
from pathlib import Path


SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "site-packages", "__pycache__", "build", "dist"}
MAX_BYTES = 1_000_000


@dataclass(frozen=True)
class Finding:
    rule_id: str
    path: str
    line: int
    end_line: int
    confidence: str
    title: str
    evidence: str
    impact: str
    check: str
    fix: str

    def to_dict(self) -> dict:
        return asdict(self)


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_name(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _name(node.func) + "()"
    return ""


def _calls(node: ast.AST) -> list[ast.Call]:
    return sorted((n for n in ast.walk(node) if isinstance(n, ast.Call)), key=lambda n: (n.lineno, n.col_offset))


def _stripe_aliases(tree: ast.AST) -> tuple[set[str], dict[str, str]]:
    roots: set[str] = set()
    resources: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.name == "stripe":
                    roots.add(item.asname or "stripe")
        elif isinstance(node, ast.ImportFrom) and node.module == "stripe":
            for item in node.names:
                if item.name in {"Charge", "PaymentIntent", "Webhook"}:
                    resources[item.asname or item.name] = item.name
    return roots, resources


def _stripe_attributes(tree: ast.AST) -> set[str]:
    roots, _ = _stripe_aliases(tree)
    return {target.id for node in ast.walk(tree)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Name)
            and node.value.id in roots}


def _is_payment(call: ast.Call, roots: set[str], resources: dict[str, str],
                stripe_attrs: set[str], legacy_charge: bool = False) -> bool:
    name = _name(call.func)
    if legacy_charge and name.endswith(".api().charges().create"):
        return True
    if any(name.endswith(f".{attr}.Charge.create") or
           name.endswith(f".{attr}.PaymentIntent.create") or
           name.endswith(f".{attr}.PaymentIntent.confirm") for attr in stripe_attrs):
        return True
    for root in roots:
        if name in {f"{root}.Charge.create", f"{root}.PaymentIntent.create", f"{root}.PaymentIntent.confirm"}:
            return True
    return any(name == f"{alias}.create" or (kind == "PaymentIntent" and name == f"{alias}.confirm")
               for alias, kind in resources.items() if kind in {"Charge", "PaymentIntent"})


def _is_webhook(call: ast.Call, roots: set[str], resources: dict[str, str]) -> bool:
    name = _name(call.func)
    return any(name == f"{root}.Webhook.construct_event" for root in roots) or any(
        name == f"{alias}.construct_event" for alias, kind in resources.items() if kind == "Webhook"
    )


def _is_local_write(call: ast.Call, roots: set[str]) -> bool:
    name = _name(call.func)
    if any(name.startswith(root + ".") for root in roots):
        return False
    if name.startswith("super().") and name.endswith(".create"):
        return True
    # Typical ORM calls. False positives remain possible; all findings are review prompts.
    if ".objects." in name and name.rsplit(".", 1)[-1] in {"create", "update", "get_or_create", "update_or_create", "bulk_create"}:
        return True
    if name.endswith(".save") or name.endswith(".session.commit") or name == "session.commit":
        return True
    return False


def _functions(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _own_calls(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Call]:
    # Do not attribute nested function bodies to their parent function.
    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.found: list[ast.Call] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is fn:
                self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            if node is fn:
                self.generic_visit(node)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_Call(self, node: ast.Call) -> None:
            self.found.append(node)
            self.generic_visit(node)

    visitor = Visitor()
    visitor.visit(fn)
    return sorted(visitor.found, key=lambda n: (n.lineno, n.col_offset))


def _has_event_id_reference(fn: ast.AST) -> bool:
    # A hint only: event-id use does not prove durable deduplication.
    for node in ast.walk(fn):
        if isinstance(node, ast.Attribute) and node.attr == "id" and isinstance(node.value, ast.Name) and node.value.id in {"event", "stripe_event"}:
            return True
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in {"event", "stripe_event"}:
            key = node.slice
            if isinstance(key, ast.Constant) and key.value == "id":
                return True
    return False


def analyze_text(source: str, path: str = "<input>", stripe_attrs: frozenset[str] = frozenset()) -> list[Finding]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(source, filename=path)
    roots, resources = _stripe_aliases(tree)
    attrs = set(stripe_attrs) | _stripe_attributes(tree)
    if not roots and not resources and not attrs:
        return []
    findings: list[Finding] = []
    legacy_functions = {id(fn) for node in ast.walk(tree)
                        if isinstance(node, ast.ClassDef) and node.name == "ChargeQuerySet"
                        for fn in node.body if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for fn in _functions(tree):
        calls = _own_calls(fn)
        writes = [c for c in calls if _is_local_write(c, roots)]
        for payment in (c for c in calls if _is_payment(c, roots, resources, attrs,
                                                        bool(attrs) and id(fn) in legacy_functions)):
            payment_name = _name(payment.func)
            intent_creation = payment_name.endswith("PaymentIntent.create") or any(
                payment_name == f"{alias}.create" for alias, kind in resources.items() if kind == "PaymentIntent"
            )
            confirmed_on_create = any(k.arg == "confirm" and isinstance(k.value, ast.Constant) and k.value.value is True
                                      for k in payment.keywords)
            provider_effect = "a PaymentIntent is created" if intent_creation and not confirmed_on_create else "payment succeeds"
            possible_impact = (
                "An orphan PaymentIntent can remain at the provider if the local write fails; whether money moves depends on subsequent confirmation."
                if intent_creation and not confirmed_on_create else
                "If payment succeeds and the local write fails, provider and database records may diverge; a retry can amplify the problem."
            )
            later = [w for w in writes if (w.lineno, w.col_offset) > (payment.lineno, payment.col_offset)]
            if later:
                findings.append(Finding(
                    "PAY001", path, payment.lineno, getattr(payment, "end_lineno", payment.lineno), "review",
                    "Provider call precedes a local write",
                    f"{payment_name} appears before {_name(later[0].func)} in {fn.name}().",
                    possible_impact,
                    f"Inject a local write failure after {provider_effect}, then retry the same business operation and inspect both systems in test mode.",
                    "Persist a stable operation ID before the provider request; reuse its idempotency key, and reconcile incomplete operations.",
                ))
            explicit_key = any(k.arg == "idempotency_key" for k in payment.keywords)
            if not explicit_key:
                forwarded = any(k.arg is None for k in payment.keywords)
                findings.append(Finding(
                    "PAY002", path, payment.lineno, getattr(payment, "end_lineno", payment.lineno), "review",
                    "No explicit idempotency key at payment call",
                    f"{_name(payment.func)} has no explicit idempotency_key argument" +
                    ("; **kwargs may supply one." if forwarded else "; another layer may still enforce safe retries."),
                    "A repeated creation request may create another payment if the same business operation is retried with a new key.",
                    "Trace retry paths and verify that the same operation reuses one stable key; test with a simulated timeout.",
                    "Bind a stable key to the business operation and persist it across retries. Review the provider's key retention window.",
                ))
        if any(_is_webhook(c, roots, resources) for c in calls) and writes and not _has_event_id_reference(fn):
            hook = next(c for c in calls if _is_webhook(c, roots, resources))
            findings.append(Finding(
                "PAY003", path, hook.lineno, getattr(hook, "end_lineno", hook.lineno), "low",
                "Webhook writes state without visible event-ID handling",
                f"{fn.name}() constructs a Stripe event and performs a local write; it has no visible event.id reference.",
                "Repeated webhook delivery may repeat a state change, depending on the write and any external deduplication.",
                "Deliver the same signed test event twice and verify one durable state transition; check helpers and database constraints.",
                "Record processed event IDs with a uniqueness constraint and make the state transition idempotent.",
            ))
    return sorted(findings, key=lambda f: (f.path, f.line, f.rule_id))


def scan(path: str | Path) -> list[Finding]:
    return scan_report(path).findings


@dataclass
class ScanReport:
    findings: list[Finding]
    skipped: list[str]
    files_analyzed: int


def scan_report(path: str | Path) -> ScanReport:
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")
    if not root.is_file() and not root.is_dir():
        raise ValueError(f"Expected a file or directory: {root}")
    if root.is_file() and root.suffix != ".py":
        raise ValueError("Expected a .py file or a directory")
    files = [root] if root.is_file() else sorted(
        p for p in root.rglob("*.py")
        if not any(part in SKIP_DIRS or part.startswith(".") for part in p.relative_to(root).parts)
    )
    findings: list[Finding] = []
    skipped: list[str] = []
    parsed: list[tuple[str, str, ast.AST]] = []
    for file in files:
        name = file.name if root.is_file() else file.relative_to(root).as_posix()
        if file.is_symlink() or file.stat().st_size > MAX_BYTES:
            skipped.append(f"{name}: symlink or file over {MAX_BYTES} bytes")
            continue
        try:
            source = file.read_text(encoding="utf-8")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(source, filename=name)
        except (UnicodeError, SyntaxError) as exc:
            skipped.append(f"{name}: cannot parse with Python 3 ({exc})")
            continue
        parsed.append((name, source, tree))
    attrs = frozenset(attr for _, _, tree in parsed for attr in _stripe_attributes(tree))
    for name, source, _ in parsed:
        findings.extend(analyze_text(source, name, attrs))
    return ScanReport(sorted(findings, key=lambda f: (f.path, f.line, f.rule_id)), skipped, len(parsed))
