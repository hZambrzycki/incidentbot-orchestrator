# src/db/connection.py

# ===========================================
# Imports
# ===========================================

import asyncio
import os
from pathlib import Path

import aiosqlite

# ===========================================
# Configuration / Globals
# ===========================================

DB_PATH = os.getenv("DB_PATH", "/data/incident-bot.sqlite3")
DB_WRITE_LOCK = asyncio.Lock()

# ===========================================
# Schema / Migration Helpers
# ===========================================


async def _column_exists(db: aiosqlite.Connection, table: str, column: str) -> bool:
    cur = await db.execute(f"PRAGMA table_info({table})")
    rows = await cur.fetchall()
    await cur.close()
    cols = {r[1] for r in rows}  # (cid, name, type, notnull, dflt_value, pk)
    return column in cols


async def _safe_add_column(
    db: aiosqlite.Connection, table: str, column: str, ddl: str
) -> None:
    if await _column_exists(db, table, column):
        return
    await db.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


async def _migrate(db: aiosqlite.Connection) -> None:
    # runbook_executions: observability  retry lineage
    await _safe_add_column(
        db, "runbook_executions", "execution_origin", "execution_origin TEXT"
    )
    await _safe_add_column(
        db, "runbook_executions", "retry_of_execution_id", "retry_of_execution_id TEXT"
    )

    # runbook_queue: backoff  lease + origin
    await _safe_add_column(
        db, "runbook_queue", "execution_origin", "execution_origin TEXT"
    )
    await _safe_add_column(
        db, "runbook_queue", "retry_of_execution_id", "retry_of_execution_id TEXT"
    )
    await _safe_add_column(db, "runbook_queue", "available_at", "available_at TEXT")
    await _safe_add_column(db, "runbook_queue", "lease_owner", "lease_owner TEXT")
    await _safe_add_column(
        db, "runbook_queue", "lease_expires_at", "lease_expires_at TEXT"
    )


async def _ensure_runbook_queue_columns(db: aiosqlite.Connection) -> None:
    # Online migration: add missing columns without dropping data.
    cur = await db.execute("PRAGMA table_info(runbook_queue)")
    cols = {row[1] for row in await cur.fetchall()}  # row[1] = name
    await cur.close()

    def missing(name: str) -> bool:
        return name not in cols

    # Columns introduced by advanced SRE recovery
    alters = []
    if missing("execution_origin"):
        alters.append("ALTER TABLE runbook_queue ADD COLUMN execution_origin TEXT;")
    if missing("retry_of_execution_id"):
        alters.append(
            "ALTER TABLE runbook_queue ADD COLUMN retry_of_execution_id TEXT;"
        )
    if missing("available_at"):
        alters.append("ALTER TABLE runbook_queue ADD COLUMN available_at TEXT;")
    if missing("lease_owner"):
        alters.append("ALTER TABLE runbook_queue ADD COLUMN lease_owner TEXT;")
    if missing("lease_expires_at"):
        alters.append("ALTER TABLE runbook_queue ADD COLUMN lease_expires_at TEXT;")

    for sql in alters:
        await db.execute(sql)

    # Backfill sane defaults (so queries/tests don't get NULL surprises)
    if alters:
        await db.execute(
            "UPDATE runbook_queue SET available_at = COALESCE(available_at, created_at) WHERE available_at IS NULL;"
        )


# ===========================================
# Public API
# ===========================================


async def init_db():
    """
    Inicializa DB + migraciones online + backfills para compatibilidad hacia atrás.
    Objetivo: que una DB vieja NO reviente el startup por NULLs en columnas nuevas.
    """
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

    async with aiosqlite.connect(DB_PATH) as db:
        # Pragmas (single bootstrap connection)
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA busy_timeout = 5000;")
        await db.execute("PRAGMA foreign_keys=ON;")
        await db.execute("PRAGMA synchronous=NORMAL;")

        # 1) Apply base scheme (helpless)

        with open("src/db/schema.sql", "r", encoding="utf-8") as f:
            await db.executescript(f.read())

        # 2) Online migrations: add columns if they are missing (your helper)
        try:
            await _migrate(db)
        except Exception:
            # don't knock down a startup because of an ALTER that already exists /rare careers
            pass

        # 3) Secures runbook_queue columns
        try:
            await _ensure_runbook_queue_columns(db)
        except Exception:
            pass

        # 4) Backfill: clear the past (avoid Pydantic Literal(None) -> crash)
        # # runbook_executions.execution_origin
        await db.execute(
            """
            UPDATE runbook_executions
            SET execution_origin = COALESCE(NULLIF(TRIM(execution_origin), ''), 'system')
            WHERE execution_origin IS NULL OR TRIM(execution_origin) = '';
            """
        )

        #    runbook_queue.execution_origin
        await db.execute(
            """
            UPDATE runbook_queue
            SET execution_origin = COALESCE(NULLIF(TRIM(execution_origin), ''), 'system')
            WHERE execution_origin IS NULL OR TRIM(execution_origin) = '';
            """
        )

        #    runbook_queue.available_at (in case old DB has NULL)
        await db.execute(
            """
            UPDATE runbook_queue
            SET available_at = COALESCE(available_at, created_at)
            WHERE available_at IS NULL;
            """
        )

        await db.commit()


async def get_db():
    # autocommit: each statement is its own transaction unless you BEGIN explicitly
    db = await aiosqlite.connect(DB_PATH, isolation_level=None)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL;")
    await db.execute("PRAGMA busy_timeout = 30000;")
    await db.execute("PRAGMA foreign_keys = ON;")
    await db.execute("PRAGMA synchronous = NORMAL;")
    try:
        yield db
    finally:
        await db.close()
