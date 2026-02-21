# src/db/__init__.py

# Public DB API
from .connection import get_db, init_db
from .event_store import emit_event, record_failure
