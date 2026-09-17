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


def _add_missing_columns():
    """Additive-only column sync for SQLite.

    `create_all` creates missing *tables* but never alters an existing one, so
    a column added to a model would silently not exist on a database created
    before it — surfacing later as "no such column" mid-scan. Only ever adds;
    never drops or retypes, so it cannot damage an existing database.
    """
    if not settings.db_is_sqlite():
        return
    from sqlalchemy import inspect, text
    insp = inspect(engine)
    existing = set(insp.get_table_names())
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing:
                continue          # create_all handles brand-new tables
            have = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in have:
                    continue
                ddl = "ALTER TABLE %s ADD COLUMN %s %s" % (
                    table.name, col.name,
                    col.type.compile(engine.dialect))
                default = getattr(col, "default", None)
                if default is not None and getattr(default, "arg", None) is not None \
                        and not callable(default.arg):
                    val = default.arg
                    if isinstance(val, bool):
                        ddl += " DEFAULT %d" % (1 if val else 0)
                    elif isinstance(val, (int, float)):
                        ddl += " DEFAULT %s" % val
                    elif isinstance(val, str):
                        ddl += " DEFAULT '%s'" % val.replace("'", "''")
                conn.execute(text(ddl))


def init_db():
    from . import models  # noqa: F401  (register tables)
    Base.metadata.create_all(bind=engine)
    _add_missing_columns()