"""Database engine and session management."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def init_engine(url: str) -> Engine:
    global _engine, _SessionLocal
    kwargs: dict = {"future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    _engine = create_engine(url, **kwargs)

    if url.startswith("sqlite"):

        @event.listens_for(_engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - driver hook
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()

    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    return _engine


def get_engine() -> Engine:
    if _engine is None:
        raise RuntimeError("Database engine not initialised")
    return _engine


def create_schema() -> None:
    from itam import models  # noqa: F401  (register mappers)
    from itam.auditlog import install_immutability_guards

    engine = get_engine()
    Base.metadata.create_all(engine)
    add_missing_columns(engine)
    install_immutability_guards(engine)


def add_missing_columns(engine: Engine) -> list[str]:
    """Upgrade an existing database in place: add nullable columns introduced by a newer release.

    ``create_all`` creates new tables but never alters existing ones. New columns on existing tables
    are always nullable, so adding them is safe; their indexes are created alongside.
    """
    from sqlalchemy import inspect
    from sqlalchemy.schema import CreateIndex

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    added: list[str] = []
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue
            present = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in present or not column.nullable:
                    continue
                col_type = column.type.compile(dialect=engine.dialect)
                conn.exec_driver_sql(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {col_type}')
                added.append(f"{table.name}.{column.name}")
                for index in table.indexes:
                    if column.name in index.columns:
                        conn.execute(CreateIndex(index, if_not_exists=True))
    return added


def new_session() -> Session:
    if _SessionLocal is None:
        raise RuntimeError("Database engine not initialised")
    return _SessionLocal()


@contextmanager
def session_scope() -> Iterator[Session]:
    session = new_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request, committed on success."""
    session = new_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def drop_all_tables() -> None:
    """Remove every application table (used only to replace an outdated demo dataset)."""
    from itam import models  # noqa: F401

    engine = get_engine()
    with engine.begin() as conn:
        if engine.dialect.name == "sqlite":
            conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
        for table in reversed(Base.metadata.sorted_tables):
            cascade = " CASCADE" if engine.dialect.name == "postgresql" else ""
            conn.exec_driver_sql(f'DROP TABLE IF EXISTS "{table.name}"{cascade}')
        if engine.dialect.name == "sqlite":
            conn.exec_driver_sql("PRAGMA foreign_keys=ON")
