"""Settings parsing for the reporting job."""


def parse_settings(raw):
    """Parses a settings literal such as "{'retries': 3, 'hosts': ['a', 'b']}"."""
    return eval(raw)
