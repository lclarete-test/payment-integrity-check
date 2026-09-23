"""Synthetic example for a local scan. Never executes during analysis."""

import stripe


def create_payment(order, **kwargs):
    charge = stripe.Charge.create(amount=order.amount, currency="usd", **kwargs)
    return PaymentRecord.objects.create(order=order, stripe_id=charge.id)
