"""Pricing rule literals for the promotions job."""
import ast


def parse_rule(raw):
    """Parses a rule literal such as "{'discount': 10, 'tiers': [1, 2]}"."""
    return ast.literal_eval(raw)
