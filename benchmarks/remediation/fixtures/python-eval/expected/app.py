"""Settings parsing for the reporting job."""
import ast


def parse_settings(raw):
    """Parses a settings literal such as "{'retries': 3, 'hosts': ['a', 'b']}"."""
    return ast.literal_eval(raw)
