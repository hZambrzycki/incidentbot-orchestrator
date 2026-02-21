# src/telegram_bot.py
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

import aiohttp

"""
Telegram Bot integration (single chat):
- Outbound notifications (incidents, runbook results)
- Inbound command polling via getUpdates
- Safe-by-default: plain text only, chunking, retries, and crash-proof loops
"""
# ============================================================
# Typing / Aliases
# ============================================================

AsyncFn = Callable[..., Awaitable[Any]]


# ============================================================
# Small helpers (time, formatting, safety)
# ============================================================


def _now() -> float:
    """Unix timestamp (seconds). Kept as helper in case we later swap time source."""
    return time.time()


def _safe(text: str) -> str:
    """
    Plain text mode (no Markdown/HTML):
    - avoids escaping issues
    - prevents formatting injection
    """
    return (text or "").strip()


def _chunk(text: str, limit: int = 3800) -> list[str]:
    """
    Telegram hard limit is 4096 chars. We use a safety margin and chunk sequentially.
    Always returns at least 1 chunk.
    """
    if not text:
        return [""]
    return [text[i : i + limit] for i in range(0, len(text), limit)]


def _short_id(x: Optional[str]) -> str:
    """Shortens long IDs for display (kept for future UI use)."""
    s = (x or "").strip()
    return s if len(s) <= 12 else s[:12]


def _emoji_for_status(status: Optional[str]) -> str:
    """Maps internal statuses to a friendly emoji."""
    s = (status or "").lower().strip()
    return {
        "pending": "⏳",
        "queued": "⏳",
        "queued_or_running": "⏳",
        "running": "⚙️",
        "success": "✅",
        "skipped": "⏭️",
        "timeout": "⏰",
        "failed": "❌",
        "error": "❌",
        "rejected": "🚫",
    }.get(s, "ℹ️")


# ============================================================
# Response formatters (backend JSON -> human text)
# ============================================================


def _format_confirm_result(out: Any) -> str:
    """
    Converts the JSON output of /confirm into readable text.
    Compatibility: if out is not a dict, fallback to str().
    """
    if not isinstance(out, dict):
        return _safe(str(out))

    success = bool(out.get("success"))
    already = bool(out.get("already_confirmed"))
    pending_id = out.get("pending_execution_id") or out.get("confirmation_id")
    confirmed_id = out.get("confirmed_execution_id")
    runbook_status = (out.get("runbook_status") or out.get("status") or "").lower()
    queue_state = (out.get("queue_state") or "").strip()  # e.g. queued_or_running

    execution = out.get("execution") or {}
    rb = execution.get("runbook_name") or out.get("runbook") or out.get("runbook_name")
    inc = execution.get("incident_id") or out.get("incident_id")
    svc = execution.get("target_service") or out.get("target_service")
    inst = execution.get("target_instance") or out.get("target_instance")

    msg = (out.get("message") or "").strip()

    # Prefer “visible state” in this order
    st = runbook_status or queue_state or (execution.get("status") or "")
    emoji = _emoji_for_status(st)

    title = "Confirmación aplicada" if success else "Confirmación fallida"
    flags: list[str] = []
    if already:
        flags.append("idempotente")
    if flags:
        title = f"{title} ({', '.join(flags)})"

    lines = [
        f"{emoji} {title}",
        "",
        f"🧾 Runbook: {rb or 'unknown'}",
        f"🆔 Pending: {pending_id or 'unknown'}",
    ]

    if confirmed_id:
        lines.append(f"✅ Confirmed: {confirmed_id}")

    if inc:
        lines.append(f"🚨 Incident: {inc}")
    if svc is not None:
        lines.append(f"🔧 Service: {svc}")
    if inst is not None:
        lines.append(f"🖥️ Instance: {inst}")

    if st:
        lines.append(f"📊 Estado: {st.upper()}")

    if msg:
        lines += ["", msg]

    return _safe("\n".join(lines))


def _format_runbook_execute_result(out: Any) -> str:
    """
    Pretty-prints result of /runbook command (accepted/pending/success/etc).
    Compatibility: if out is not a dict, fallback to str().
    """
    if not isinstance(out, dict):
        return _safe(str(out))

    accepted = out.get("accepted")
    ex_id = out.get("execution_id") or out.get("id")
    rb = out.get("runbook") or out.get("runbook_name")
    st = (out.get("status") or "").lower()
    svc = out.get("target_service")
    inst = out.get("target_instance")
    inc = out.get("incident_id")

    emoji = _emoji_for_status(st)
    header = "Runbook recibido" if accepted else "Runbook rechazado"

    lines = [
        f"{emoji} {header}",
        "",
        f"🧾 Runbook: {rb or 'unknown'}",
    ]
    if ex_id:
        lines.append(f"🆔 Execution: {ex_id}")
    if inc:
        lines.append(f"🚨 Incident: {inc}")
    if svc is not None:
        lines.append(f"🔧 Service: {svc}")
    if inst is not None:
        lines.append(f"🖥️ Instance: {inst}")
    if st:
        lines.append(f"📊 Estado: {st.upper()}")

    if st == "pending":
        lines += ["", "👉 Usa /pending para verlos y /confirm <id> para ejecutar."]

    return _safe("\n".join(lines))


# ============================================================
# Configuration
# ============================================================


@dataclass
class TelegramConfig:
    enabled: bool
    token: str
    chat_id: str
    poll_interval_seconds: float = 1.0
    request_timeout_seconds: float = 35.0
    max_updates_per_call: int = 20
    allowed_chat_id_only: bool = True


# ============================================================
# Telegram Bot (polling + commands + notifications)
# ============================================================


class _TelegramBot:
    """
    Telegram integration (single chat_id):

    - notify_*: outbound notifications
    - polling loop: listens to commands (getUpdates)
    - fail-safe: exceptions never crash your app; everything logs & continues
    """

    # --------------------------------------------------------
    # Lifecycle / wiring
    # --------------------------------------------------------

    def __init__(self) -> None:
        self._cfg: Optional[TelegramConfig] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._poll_task: Optional[asyncio.Task] = None
        self._stop_evt = asyncio.Event()
        self._offset: int = 0

        # callbacks (wired from main.py)
        self._cb_get_status: Optional[AsyncFn] = None
        self._cb_list_incidents: Optional[AsyncFn] = None
        self._cb_runbook_execute: Optional[AsyncFn] = None
        self._cb_runbook_history: Optional[AsyncFn] = None
        self._cb_pending: Optional[AsyncFn] = None
        self._cb_confirm: Optional[AsyncFn] = None
        self._cb_skip: Optional[AsyncFn] = None

        self._logger = None

    def set_logger(self, logger: Any) -> None:
        """Inject a logger with .info/.warning/... methods."""
        self._logger = logger

    def configure(self, cfg: TelegramConfig) -> None:
        """Set bot configuration (token, chat_id, etc)."""
        self._cfg = cfg

    def set_callbacks(
        self,
        *,
        get_status: Optional[AsyncFn] = None,
        list_incidents: Optional[AsyncFn] = None,
        runbook_execute: Optional[AsyncFn] = None,
        runbook_history: Optional[AsyncFn] = None,
        pending: Optional[AsyncFn] = None,
        confirm: Optional[AsyncFn] = None,
        skip: Optional[AsyncFn] = None,
    ) -> None:
        """Wire backend callbacks used by commands."""
        self._cb_get_status = get_status
        self._cb_list_incidents = list_incidents
        self._cb_runbook_execute = runbook_execute
        self._cb_runbook_history = runbook_history
        self._cb_pending = pending
        self._cb_confirm = confirm
        self._cb_skip = skip

    async def initialize(self) -> None:
        """
        Prepare HTTP session and validate credentials (optional fast-fail with getMe).
        Should be called once at startup.
        """
        if not self._cfg or not self._cfg.enabled:
            return

        if not self._cfg.token or not self._cfg.chat_id:
            raise RuntimeError(
                "Telegram enabled but TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID missing"
            )

        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self._cfg.request_timeout_seconds)
            self._session = aiohttp.ClientSession(timeout=timeout)

        # Validate token by calling getMe (fails fast)
        me = await self._api("getMe", {})
        if not me.get("ok"):
            raise RuntimeError(f"Telegram getMe failed: {me}")

        self._log(
            "info", "telegram_initialized", bot=me.get("result", {}).get("username")
        )

    async def start(self) -> None:
        """Start polling loop (idempotent)."""
        if not self._cfg or not self._cfg.enabled:
            return
        if self._poll_task and not self._poll_task.done():
            return

        self._stop_evt.clear()
        self._poll_task = asyncio.create_task(
            self._poll_loop(), name="telegram_poll_loop"
        )
        self._log("info", "telegram_started")

    async def stop(self) -> None:
        """Stop polling loop and close the HTTP session (best-effort)."""
        if not self._cfg or not self._cfg.enabled:
            return

        self._stop_evt.set()

        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except Exception:
                pass

        if self._session and not self._session.closed:
            await self._session.close()

        self._log("info", "telegram_stopped")

    # --------------------------------------------------------
    # Outbound notifications
    # --------------------------------------------------------

    async def notify_incident(self, incident: Any) -> None:
        """
        Called when an incident is created/updated.
        Expects incident to have .id, .severity, and .title/.summary (adjust as needed).
        """
        if not self._cfg or not self._cfg.enabled:
            return

        inc_id = getattr(incident, "id", "unknown")
        sev = getattr(incident, "severity", "unknown")
        title = (
            getattr(incident, "title", None)
            or getattr(incident, "summary", None)
            or "Incident"
        )

        msg = _safe(f"🚨 INCIDENT\nID: {inc_id}\nSeverity: {sev}\n{title}")
        await self._send(msg)

    async def notify_runbook_result(
        self,
        *,
        runbook_name: str,
        success: bool,
        message: str,
        incident_id: Optional[str] = None,
    ) -> None:
        """Outbound message for completed runbooks (optional helper)."""
        if not self._cfg or not self._cfg.enabled:
            return

        status_emoji = "✅" if success else "❌"
        inc = f"\nIncident: {incident_id}" if incident_id else ""
        body = _safe(message)

        msg = _safe(
            f"{status_emoji} RUNBOOK RESULT\nRunbook: {runbook_name}{inc}\n{body}"
        )
        await self._send(msg)

    # --------------------------------------------------------
    # Polling loop + update dispatch
    # --------------------------------------------------------

    async def _poll_loop(self) -> None:
        """
        Long-polling loop for inbound commands.
        Notes:
        - uses getUpdates with timeout=20 to reduce request rate
        - offset is advanced after each update_id
        - errors are swallowed to keep the app alive
        """
        assert self._cfg is not None

        while not self._stop_evt.is_set():
            try:
                updates = await self._api(
                    "getUpdates",
                    {
                        "offset": self._offset,
                        "limit": self._cfg.max_updates_per_call,
                        "timeout": 20,
                        "allowed_updates": ["message"],
                    },
                )

                if not updates.get("ok"):
                    self._log("warning", "telegram_getupdates_failed", resp=updates)
                    await asyncio.sleep(2.0)
                    continue

                for upd in updates.get("result", []) or []:
                    self._offset = max(self._offset, int(upd.get("update_id", 0)) + 1)
                    await self._handle_update(upd)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self._log("warning", "telegram_poll_loop_error", error=str(e))
                await asyncio.sleep(2.0)

            await asyncio.sleep(self._cfg.poll_interval_seconds)

    async def _handle_update(self, upd: dict) -> None:
        """Routes a Telegram update to the right command handler."""
        msg = upd.get("message") or {}
        text = (msg.get("text") or "").strip()

        # Only commands
        if not text.startswith("/"):
            return

        chat = msg.get("chat") or {}
        chat_id = str(chat.get("id", ""))

        # Optional: restrict to one chat (fail-closed)
        if self._cfg and self._cfg.allowed_chat_id_only:
            if chat_id != str(self._cfg.chat_id):
                self._log(
                    "warning", "telegram_ignored_unauthorized_chat", chat_id=chat_id
                )
                return

        parts = text.split()
        cmd = parts[0].lower()
        args = parts[1:]

        # Core help
        if cmd in ("/start", "/help"):
            await self._send(self._help_text())
            return

        # Commands
        if cmd == "/status":
            await self._cmd_status()
            return
        if cmd == "/incidents":
            await self._cmd_incidents()
            return
        if cmd == "/runbook":
            await self._cmd_runbook(args)
            return
        if cmd == "/history":
            await self._cmd_history()
            return
        if cmd == "/pending":
            await self._cmd_pending()
            return

        # Optional confirmation hooks
        if cmd == "/confirm":
            await self._cmd_confirm(args, chat_id=chat_id)
            return
        if cmd == "/skip":
            await self._cmd_skip(args)
            return

        await self._send("🤖 Comando no reconocido. Usa /help.")

    # --------------------------------------------------------
    # Command handlers
    # --------------------------------------------------------

    def _help_text(self) -> str:
        """Static help payload."""
        return _safe(
            "🤖 IncidentBot — comandos\n\n"
            "/status — estado general\n"
            "/incidents — incidentes activos\n"
            "/runbook <name> [k=v ...] — ejecutar runbook (si tu backend lo permite)\n"
            "/history — últimas ejecuciones\n"
            "/pending — pendings confirmables (ids para /confirm y /skip)\n"
            "/confirm <confirmation_id> — (opcional) confirmar runbook pendiente\n"
            "/skip <confirmation_id> — (opcional) cancelar runbook pendiente\n"
        )

    async def _cmd_status(self) -> None:
        if not self._cb_get_status:
            await self._send("⚠️ /status no está cableado aún.")
            return
        try:
            data = await self._cb_get_status()
            await self._send(_safe(str(data)))
        except Exception as e:
            self._log("warning", "telegram_cmd_status_failed", error=str(e))
            await self._send("❌ Error obteniendo status.")

    async def _cmd_incidents(self) -> None:
        if not self._cb_list_incidents:
            await self._send("⚠️ /incidents no está cableado aún.")
            return
        try:
            items = await self._cb_list_incidents()
            if not items:
                await self._send("✅ No hay incidentes activos.")
                return

            lines = ["🚨 Incidentes activos:"]
            for it in items[:20]:
                if isinstance(it, dict):
                    pend = it.get("pending_confirmations") or []
                    pend_ids = [
                        (p.get("id") if isinstance(p, dict) else str(p))
                        for p in pend[:6]
                    ]
                    extra = (
                        f"\n  pending_confirmations: {', '.join(pend_ids)}"
                        if pend_ids
                        else ""
                    )
                    lines.append(
                        f"- {it.get('id')} [{it.get('severity')}] "
                        f"{it.get('title') or it.get('summary')}{extra}"
                    )
                else:
                    lines.append(
                        f"- {getattr(it, 'id', '?')} [{getattr(it, 'severity', '?')}] "
                        f"{getattr(it, 'title', None) or getattr(it, 'summary', '')}"
                    )

            await self._send(_safe("\n".join(lines)))

        except Exception as e:
            self._log("warning", "telegram_cmd_incidents_failed", error=str(e))
            await self._send("❌ Error listando incidentes.")

    async def _cmd_runbook(self, args: list[str]) -> None:
        if not self._cb_runbook_execute:
            await self._send("⚠️ /runbook no está cableado aún.")
            return
        if not args:
            await self._send("Uso: /runbook <name> [k=v ...]")
            return

        name = args[0]
        kv: dict[str, str] = {}
        for raw in args[1:]:
            if "=" in raw:
                k, v = raw.split("=", 1)
                kv[k.strip()] = v.strip()

        try:
            result = await self._cb_runbook_execute(runbook_name=name, params=kv)
            self._log(
                "info", "telegram_cmd_runbook_parsed", name=name, kv=kv, raw_args=args
            )
            await self._send(_format_runbook_execute_result(result))
        except Exception as e:
            self._log(
                "warning", "telegram_cmd_runbook_failed", error=str(e), runbook=name
            )
            await self._send("❌ Error ejecutando runbook.")

    async def _cmd_history(self) -> None:
        if not self._cb_runbook_history:
            await self._send("⚠️ /history no está cableado aún.")
            return
        try:
            items = await self._cb_runbook_history()
            if not items:
                await self._send("🕰️ Sin historial reciente.")
                return

            lines = ["🕰️ Últimas ejecuciones:"]
            for it in items[:20]:
                if isinstance(it, dict):
                    ok = it.get("status") or it.get("success")
                    lines.append(
                        f"- {it.get('runbook_name')} → {ok} ({it.get('completed_at')})"
                    )
                else:
                    lines.append(
                        f"- {getattr(it, 'runbook_name', '?')} → {getattr(it, 'status', '?')} "
                        f"({getattr(it, 'completed_at', '')})"
                    )

            await self._send(_safe("\n".join(lines)))

        except Exception as e:
            self._log("warning", "telegram_cmd_history_failed", error=str(e))
            await self._send("❌ Error obteniendo historial.")

    async def _cmd_pending(self) -> None:
        if not self._cb_pending:
            await self._send("⚠️ /pending no está cableado aún.")
            return
        try:
            items = await self._cb_pending()
            if not items:
                await self._send("✅ No hay pendings confirmables.")
                return

            lines = ["⏳ Pendings confirmables (usa /confirm o /skip):"]
            for it in items[:40]:
                cid = (
                    it.get("confirmation_id")
                    or it.get("pending_execution_id")
                    or it.get("id")
                )
                age = it.get("age_seconds")
                rb = it.get("runbook_name") or it.get("runbook")
                inc = it.get("incident_id")
                svc = it.get("target_service")
                lines.append(f"- {cid} | {rb} | inc={inc} | svc={svc} | age={age}s")

            await self._send(_safe("\n".join(lines)))

        except Exception as e:
            self._log("warning", "telegram_cmd_pending_failed", error=str(e))
            await self._send("❌ Error obteniendo pendings.")

    async def _cmd_confirm(self, args: list[str], *, chat_id: str) -> None:
        if not self._cb_confirm:
            await self._send("⚠️ /confirm no está cableado aún.")
            return
        if not args:
            await self._send("Uso: /confirm <confirmation_id>")
            return
        try:
            out = await self._cb_confirm(confirmation_id=args[0], chat_id=chat_id)
            await self._send(_format_confirm_result(out))
        except Exception as e:
            self._log("warning", "telegram_cmd_confirm_failed", error=str(e))
            await self._send("❌ Error confirmando.")

    async def _cmd_skip(self, args: list[str]) -> None:
        if not self._cb_skip:
            await self._send("⚠️ /skip no está cableado aún.")
            return
        if not args:
            await self._send("Uso: /skip <confirmation_id>")
            return
        try:
            out = await self._cb_skip(confirmation_id=args[0])
            await self._send(_safe(str(out)))
        except Exception as e:
            self._log("warning", "telegram_cmd_skip_failed", error=str(e))
            await self._send("❌ Error cancelando.")

    # --------------------------------------------------------
    # Telegram HTTP API (send + low-level _api)
    # --------------------------------------------------------

    async def _send(self, text: str) -> None:
        """Send a message, chunking to avoid Telegram message size limits."""
        assert self._cfg is not None
        for part in _chunk(_safe(text)):
            await self._api(
                "sendMessage",
                {
                    "chat_id": self._cfg.chat_id,
                    "text": part,
                    "disable_web_page_preview": True,
                },
            )

    async def _api(self, method: str, payload: dict) -> dict:
        """
        Low-level Telegram API wrapper:
        - ensures session exists
        - retries transient errors
        - returns dict {"ok": bool, ...}
        """
        assert self._cfg is not None

        if not self._session or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self._cfg.request_timeout_seconds)
            self._session = aiohttp.ClientSession(timeout=timeout)

        url = f"https://api.telegram.org/bot{self._cfg.token}/{method}"

        last_err: Optional[BaseException] = None
        for attempt in range(3):
            try:
                async with self._session.post(url, json=payload) as resp:
                    data = await resp.json(content_type=None)
                    return (
                        data
                        if isinstance(data, dict)
                        else {"ok": False, "error": "non_dict_response"}
                    )
            except Exception as e:
                last_err = e
                await asyncio.sleep(0.4 * (attempt + 1))

        self._log(
            "warning",
            "telegram_api_failed",
            method=method,
            error=str(last_err),
            error_type=type(last_err).__name__ if last_err else None,
            error_repr=repr(last_err) if last_err else None,
        )
        return {"ok": False, "error": repr(last_err)}

    # --------------------------------------------------------
    # Logging
    # --------------------------------------------------------

    def _log(self, level: str, event: str, **fields: Any) -> None:
        """Best-effort structured logging (never raises)."""
        if self._logger is None:
            return
        try:
            fn = getattr(self._logger, level, None) or getattr(self._logger, "info")
            fn(event, **fields)
        except Exception:
            pass


# ============================================================
# Singleton instance
# ============================================================

telegram_bot = _TelegramBot()
