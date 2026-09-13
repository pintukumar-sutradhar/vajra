"""VAJRA platform database plumbing (SQLAlchemy).

SQLite is used in WAL mode with a generous busy timeout so the API process,
the worker process and the report/recovery code can read and write the same
database concurrently without deadlocking on each other's locks.
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import settings

connect_args = {"check_same_thread": False,
                "timeout": 30} if settings.db_is_sqlite() else {}
engine = create_engine(settings.db_url, connect_args=connect_args)


def _sqlite_tune(dbapi_conn, _record):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.execute("PRAGMA busy_timeout=30000")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


if settings.db_is_sqlite():
    event.listen(engine, "connect", _sqlite_tune)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False,
                            expire_on_commit=True)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from . import models  # noqa: F401  (register tables)
    Base.metadata.create_all(bind=engine)