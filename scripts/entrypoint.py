#!/usr/bin/env python3
"""Container entrypoint.

Waits for PostgreSQL, seeds the database (idempotent), then hands off to
uvicorn. Kept as Python so it works on the slim image without bash tricks.
"""

import os
import sys
import time

import sqlalchemy
from sqlalchemy import text


def wait_for_database(timeout: int = 90):
    url = os.getenv("DATABASE_URL", "")
    if not url:
        print("DATABASE_URL not set; skipping wait")
        return
    engine = sqlalchemy.create_engine(url)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            print("PostgreSQL is ready")
            return
        except Exception as exc:
            print(f"Waiting for PostgreSQL... ({exc.__class__.__name__})")
            time.sleep(2)
    raise SystemExit("Timed out waiting for PostgreSQL")


def main():
    wait_for_database()

    seed = os.path.join(os.path.dirname(__file__), "seed_database.py")
    result = os.system(f"{sys.executable} {seed}")
    if result != 0:
        print("Seeding reported errors; continuing anyway")


if __name__ == "__main__":
    main()