"""Pricing rule literals for the promotions job."""


def parse_rule(raw):
    """Parses a rule literal such as "{'discount': 10, 'tiers': [1, 2]}"."""
    namespace = {}
    exec("rule = " + raw, namespace)
    return namespace["rule"]
