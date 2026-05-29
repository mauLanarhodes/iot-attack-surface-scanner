"""Database engine and session factory."""

from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

DB_DIR  = Path.home() / ".iotscanner"
DB_PATH = DB_DIR / "scanner.db"


def _migrate(engine) -> None:
    """Add any columns introduced after a DB was first created.

    SQLAlchemy's create_all() never alters existing tables, so new columns on
    the Device model are added here via ALTER TABLE (SQLite supports this for
    simple column adds). Keeps older scanner.db files forward-compatible.
    """
    insp = inspect(engine)
    if "devices" not in insp.get_table_names():
        return
    existing = {col["name"] for col in insp.get_columns("devices")}
    # column_name -> SQL type
    wanted = {
        "open_ports": "JSON",
    }
    to_add = {name: typ for name, typ in wanted.items() if name not in existing}
    if to_add:
        with engine.begin() as conn:
            for name, typ in to_add.items():
                conn.execute(text(f"ALTER TABLE devices ADD COLUMN {name} {typ}"))


def _get_engine():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{DB_PATH}", echo=False)
    Base.metadata.create_all(engine)
    _migrate(engine)
    return engine


_engine         = None
_SessionFactory = None


def _init():
    global _engine, _SessionFactory
    if _engine is None:
        _engine         = _get_engine()
        _SessionFactory = sessionmaker(bind=_engine)


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """Yield a SQLAlchemy session, committing on success and rolling back on error."""
    _init()
    session = _SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()