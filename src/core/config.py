from functools import lru_cache
from typing import Optional, Set

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # ---------------------------------------
    # Pydantic settings config
    # ---------------------------------------
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---------------------------------------
    # Global guardrails
    # ---------------------------------------
    # Comma-separated allowlist, e.g.: "frontend,nginx,postgres"
    # Empty or "*" means allow all (you decide policy below).
    allowed_target_services: Optional[str] = Field(
        default=None, validation_alias="ALLOWED_TARGET_SERVICES"
    )

    @property
    def allowed_target_services_set(self) -> Optional[Set[str]]:
        """
        Normalized allowlist for registry.can_target_service().
        - None / "" => no global restriction (return None)
        - "*" => no restriction (return {"*"})
        """
        raw = (self.allowed_target_services or "").strip()
        if not raw:
            return None
        items = {p.strip().lower() for p in raw.split(",") if p.strip()}
        return items or None

    # ---------------------------------------
    # Application
    # ---------------------------------------
    app_name: str = Field(default="incident-bot", validation_alias="APP_NAME")
    app_env: str = Field(default="development", validation_alias="APP_ENV")
    debug: bool = Field(default=False, validation_alias="DEBUG")
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")

    # ---------------------------------------
    # API Server
    # ---------------------------------------
    api_host: str = Field(default="0.0.0.0", validation_alias="API_HOST")
    api_port: int = Field(default=8000, validation_alias="API_PORT")

    # ---------------------------------------
    # Security
    # ---------------------------------------
    admin_token: Optional[str] = Field(default=None, validation_alias="ADMIN_TOKEN")
    admin_tokens: Optional[str] = Field(default=None, validation_alias="ADMIN_TOKENS")
    admin_allow_bearer: bool = Field(
        default=True, validation_alias="ADMIN_ALLOW_BEARER"
    )

    rate_limit_key_mode: str = Field(
        default="token_or_ip", validation_alias="RATE_LIMIT_KEY_MODE"
    )
    rate_limit_window_seconds: int = Field(
        default=60, validation_alias="RATE_LIMIT_WINDOW_SECONDS"
    )
    rate_limit_confirm_max: int = Field(
        default=5, validation_alias="RATE_LIMIT_CONFIRM_MAX"
    )
    rate_limit_runbook_max: int = Field(
        default=10, validation_alias="RATE_LIMIT_RUNBOOK_MAX"
    )

    # ---------------------------------------
    # Telegram
    # ---------------------------------------
    telegram_bot_token: Optional[str] = Field(
        default=None, validation_alias="TELEGRAM_BOT_TOKEN"
    )
    telegram_chat_id: Optional[str] = Field(
        default=None, validation_alias="TELEGRAM_CHAT_ID"
    )
    telegram_enabled: bool = Field(default=False, validation_alias="TELEGRAM_ENABLED")

    # ---------------------------------------
    # Observability / Integrations
    # ---------------------------------------
    prometheus_url: str = Field(
        default="http://prometheus:9090", validation_alias="PROMETHEUS_URL"
    )
    alertmanager_url: str = Field(
        default="http://alertmanager:9093", validation_alias="ALERTMANAGER_URL"
    )

    # ---------------------------------------
    # Runbooks / Recovery
    # ---------------------------------------
    runbook_timeout: int = Field(default=300, validation_alias="RUNBOOK_TIMEOUT")
    runbook_auto_execute: bool = Field(
        default=True, validation_alias="RUNBOOK_AUTO_EXECUTE"
    )
    runbook_require_confirmation: bool = Field(
        default=True, validation_alias="RUNBOOK_REQUIRE_CONFIRMATION"
    )

    # Retry policy (durable queue)
    runbook_max_retries: int = Field(default=2, validation_alias="RUNBOOK_MAX_RETRIES")
    runbook_retry_backoff_base_seconds: int = Field(
        default=5, validation_alias="RUNBOOK_RETRY_BACKOFF_BASE_SECONDS"
    )
    runbook_retry_backoff_max_seconds: int = Field(
        default=120, validation_alias="RUNBOOK_RETRY_BACKOFF_MAX_SECONDS"
    )

    # Lease (exactly-once-ish)
    runbook_lease_seconds: int = Field(
        default=30, validation_alias="RUNBOOK_LEASE_SECONDS"
    )

    # Concurrency por servicio (además del global semaphore)
    # Formato: "nginx=1,postgres=1,frontend=2"
    runbook_service_concurrency: Optional[str] = Field(
        default=None, validation_alias="RUNBOOK_SERVICE_CONCURRENCY"
    )

    # Hardening: límite global de runbooks concurrentes en estado RUNNING
    runbook_max_concurrent: int = Field(
        default=5, validation_alias="RUNBOOK_MAX_CONCURRENT"
    )

    # Queue housekeeping (si quieres por env, añade validation_alias)
    runbook_queue_heartbeat_seconds: int = 5
    runbook_queue_stale_running_seconds: int = 30

    # Pending confirmations / escalation
    confirm_ttl_seconds: int = Field(
        default=86400,
        validation_alias="CONFIRM_TTL_SECONDS",
    )
    pending_reminder_thresholds_seconds: Optional[str] = Field(
        default=None, validation_alias="PENDING_REMINDER_THRESHOLDS_SECONDS"
    )
    pending_reminder_loop_interval_seconds: int = Field(
        default=60, validation_alias="PENDING_REMINDER_LOOP_INTERVAL_SECONDS"
    )

    # ---------------------------------------
    # Logging
    # ---------------------------------------
    log_format: str = Field(default="json", validation_alias="LOG_FORMAT")
    log_file: str = Field(
        default="/var/log/incident-bot/app.log", validation_alias="LOG_FILE"
    )
    audit_log_file: str = Field(
        default="/var/log/incident-bot/audit.log", validation_alias="AUDIT_LOG_FILE"
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        vv = v.upper()
        if vv not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return vv

    # ---------------------------------------
    # Derived helpers
    # ---------------------------------------
    @property
    def pending_reminder_thresholds_list(self) -> list[int]:
        raw = (self.pending_reminder_thresholds_seconds or "").strip()
        if not raw:
            return [600, 3600, 21600]
        out: list[int] = []
        for part in raw.split(","):
            p = part.strip()
            if not p:
                continue
            try:
                val = int(p)
                if val > 0:
                    out.append(val)
            except Exception:
                continue
        out = sorted(set(out))
        return out or [600, 3600, 21600]

    @property
    def telegram_configured(self) -> bool:
        return bool(
            self.telegram_bot_token and self.telegram_chat_id and self.telegram_enabled
        )

    @property
    def admin_token_list(self) -> list[str]:
        toks: list[str] = []
        if self.admin_token:
            toks.append(self.admin_token.strip())
        if self.admin_tokens:
            toks.extend([t.strip() for t in self.admin_tokens.split(",") if t.strip()])

        seen = set()
        out: list[str] = []
        for t in toks:
            if t and t not in seen:
                out.append(t)
                seen.add(t)
        return out


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
