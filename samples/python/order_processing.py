"""Order processing helpers with a few real-world smells (labelled)."""
import logging
from dataclasses import dataclass, field
from typing import List

LOG = logging.getLogger(__name__)
TAX_RATE = 0.2
FREE_SHIPPING_LIMIT = 50


@dataclass
class Order:
    """A customer order."""
    customer: str
    items: List[float] = field(default_factory=list)

    def subtotal(self):
        """Return the sum of item prices."""
        return sum(self.items)


def shipping_cost(order):
    """Return the shipping cost for an order."""
    if order.subtotal() >= FREE_SHIPPING_LIMIT:
        return 0
    return 4.99  # EXPECT: MAGIC_NUMBER


def apply_discount(order, code):
    """Return the discounted subtotal."""
    total = order.subtotal()
    if code == "SAVE10":
        return total * 0.9  # EXPECT: MAGIC_NUMBER
    return total


def checkout(order, payment, retries=3):
    """Charge the payment and log the outcome."""
    for attempt in range(retries):
        try:
            payment.charge(order.subtotal() * (1 + TAX_RATE))
            LOG.info("charged %s", order.customer)
            return True
        except ConnectionError as exc:
            LOG.warning("attempt %d failed: %s", attempt, exc)
    return False
