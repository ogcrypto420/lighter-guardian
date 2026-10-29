"""
Защита данных стража:

  • allowlist: программа может ходить в сеть только на адреса Lighter и Telegram — всё остальное блокируется;
  • redaction: секреты (ключи, токены, пароли прокси) вымарываются из логов и сообщений;
  • hardening: запрет дампов памяти процесса (в них могли бы оказаться ключи);
  • privacy: уровни подробности уведомлений Telegram (full / short / minimal).
"""
from __future__ import annotations

import ctypes
import logging
import os
import re
import sys
from urllib.parse import urlsplit

# ───────────────────────────── вымарывание секретов ─────────────────────────────

_secrets: set[str] = set()


def register_secret(value: str | None) -> None:
    """Запомнить строку, которую нельзя показывать никогда (ключ, токен, пароль прокси)."""
    if not value or len(value) < 6:
        return
    _secrets.add(value)
    if value.startswith("0x"):
        _secrets.add(value[2:])
    # у прокси секретна часть «логин:пароль»
    m = re.match(r"^\w+://([^@/]+)@", value)
    if m:
        _secrets.add(m.group(1))


# auth-токены Lighter: {expiry}:{account}:{key}:{hex}
_TOKEN_RE = re.compile(r"\b\d{9,11}:\d+:\d+:[0-9a-fA-F]{16,}\b")
_URL_CRED_RE = re.compile(r"(\w+://)[^@/\s]+@")


def redact(text: str) -> str:
    if not text:
        return text
    for s in sorted(_secrets, key=len, reverse=True):
        if s in text:
            text = text.replace(s, "«скрыто»")
    text = _TOKEN_RE.sub("«токен скрыт»", text)
    return _URL_CRED_RE.sub(r"\1«скрыто»@", text)


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        clean = redact(msg)
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        if clean != msg or record.args:
            record.msg, record.args = clean, None
        return True


def install_log_redaction() -> None:
    root = logging.getLogger()
    f = RedactingFilter()
    root.addFilter(f)
    for h in root.handlers:
        h.addFilter(f)


# ───────────────────────────── белый список адресов ─────────────────────────────

class BlockedHost(RuntimeError):
    pass


class SafeSession:
    """Обёртка над aiohttp.ClientSession: запросы только на разрешённые хосты, только https/wss."""

    def __init__(self, session, allowed_hosts: set[str]):
        self._s = session
        self.allowed = {h.lower() for h in allowed_hosts}

    def _check(self, url: str) -> None:
        u = urlsplit(str(url))
        host = (u.hostname or "").lower()
        if u.scheme not in ("https", "wss") or host not in self.allowed:
            raise BlockedHost(f"Заблокировано обращение к {u.scheme}://{host} — его нет в белом списке")

    def get(self, url, **kw):
        self._check(url)
        return self._s.get(url, **kw)

    def post(self, url, **kw):
        self._check(url)
        return self._s.post(url, **kw)

    def ws_connect(self, url, **kw):
        self._check(url)
        return self._s.ws_connect(url, **kw)


# ───────────────────────────── защита процесса ─────────────────────────────

def harden_process() -> list[str]:
    """Запрещаем дампы памяти и подключение отладчиков от того же пользователя (Linux)."""
    done = []
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        done.append("дампы памяти отключены")
    except Exception:  # noqa: BLE001
        pass
    if sys.platform.startswith("linux"):
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            PR_SET_DUMPABLE = 4
            if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0:
                done.append("чтение памяти процесса другими программами запрещено")
        except Exception:  # noqa: BLE001
            pass
    if hasattr(os, "umask"):
        os.umask(0o077)          # все создаваемые файлы — только для владельца
        done.append("новые файлы доступны только владельцу")
    return done


# ───────────────────────────── подробность уведомлений ─────────────────────────────
# В текстах сообщений чувствительные части помечаются:
#   S(…) — цифры: размеры позиций, цены, номера аккаунтов, адреса прокси;
#   T(…) — тикеры.
# full — всё как есть; short — без цифр; minimal — без цифр и тикеров.

_S0, _S1, _T0, _T1 = "", "", "", ""
LEVELS = ("full", "short", "minimal")


def S(x) -> str:
    return f"{_S0}{x}{_S1}"


def T(x) -> str:
    return f"{_T0}{x}{_T1}"


def render(text: str, level: str) -> str:
    if level == "full":
        out = text
    else:
        out = re.sub(f"{_S0}.*?{_S1}", "•••", text, flags=re.S)
        if level == "minimal":
            out = re.sub(f"{_T0}.*?{_T1}", "•••", out, flags=re.S)
    return out.replace(_S0, "").replace(_S1, "").replace(_T0, "").replace(_T1, "")


def strip_marks(text: str) -> str:
    return render(text, "full")
