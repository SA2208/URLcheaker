from __future__ import annotations

import argparse
import hashlib
import hmac
import os
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Create an HMAC sidecar for a trusted model")
    parser.add_argument("model", type=Path, help="PyCaret .pkl artifact")
    args = parser.parse_args()

    key = os.environ.get("URLCHECKER_MODEL_HMAC_KEY", "")
    if len(key) < 32:
        raise SystemExit("URLCHECKER_MODEL_HMAC_KEY must contain at least 32 characters")
    if not args.model.is_file():
        raise SystemExit(f"Model not found: {args.model}")

    signature = hmac.new(key.encode(), args.model.read_bytes(), hashlib.sha256).hexdigest()
    output = args.model.with_suffix(args.model.suffix + ".hmac")
    output.write_text(signature + "\n", encoding="ascii")
    print(output)


if __name__ == "__main__":
    main()
