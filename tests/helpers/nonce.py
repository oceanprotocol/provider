from datetime import datetime, timezone


def build_nonce():
    return str(datetime.now(timezone.utc).timestamp() * 1000)
