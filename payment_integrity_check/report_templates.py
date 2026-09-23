"""Editable, deterministic explanations for the enabled checks."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleTemplate:
    id: str
    title: str
    question: str
    why: str
    limits: str


RULE_TEMPLATES = (
    RuleTemplate(
        "PAY001", "Provider action before local record",
        "Can an external payment operation run before the application records it?",
        "A provider request and a local database write are separate operations. If the first completes and the second fails, the two systems may disagree. A later retry needs a stable operation ID and reconciliation path.",
        "Source order is a clue, not proof that both statements run on the same path or that the application has no recovery mechanism. Creating an unconfirmed PaymentIntent does not by itself charge a customer.",
    ),
    RuleTemplate(
        "PAY002", "Idempotency at the payment call",
        "Does a retry visibly reuse a key tied to the same business operation?",
        "When the same write request is retried, reusing an operation-specific idempotency key helps prevent duplicate provider actions. The key must stay the same across retries of that operation.",
        "The scanner checks for an explicit keyword at the call site. A wrapper or **kwargs can supply it, and an explicit keyword does not prove that its value stays stable across retries.",
    ),
    RuleTemplate(
        "PAY003", "Repeated webhook delivery",
        "Does a webhook handler visibly use the event ID when it changes local state?",
        "Payment event delivery can be repeated. Without durable deduplication or an idempotent state transition, processing the same event twice may repeat a local change.",
        "Using event.id is only a hint, not proof of safe processing. Another component may deduplicate events, and the scanner recognizes only the supported Stripe webhook pattern.",
    ),
)


def template_for(rule_id: str) -> RuleTemplate:
    return next(template for template in RULE_TEMPLATES if template.id == rule_id)
