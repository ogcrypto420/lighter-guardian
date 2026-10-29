#!/usr/bin/env python3
"""
Зашифрованное хранилище секретов стража: API-ключи, адреса, прокси, токен Telegram.

Шифрование: AES-256-GCM, ключ выводится из мастер-пароля через scrypt (N=2^16, r=8, p=1).
Файл хранилища без пароля бесполезен; пароль нигде не сохраняется.

    python vault.py init              создать хранилище
    python vault.py set TG_TOKEN      записать значение (ввод скрыт)
    python vault.py set TG_CHAT_ID 123456789
    python vault.py list              что лежит в хранилище (значения скрыты)
    python vault.py remove W2_PROXY   удалить запись
    python vault.py import .env       перенести секреты из .env и стереть их там
    python vault.py passwd            сменить пароль
"""
from __future__ import annotations

import base64
import getpass
import json
import os
import re
import secrets
import stat
import sys
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

HERE = Path(__file__).resolve().parent
DEFAULT_PATH = Path(os.getenv("GUARDIAN_VAULT", str(HERE / "guardian.vault")))
FORMAT = "lighter-guardian-vault"
KDF_N, KDF_R, KDF_P = 2 ** 16, 8, 1
MIN_PASSWORD = 10

# Что считается секретом и не должно лежать в .env открытым текстом
SECRET_PATTERNS = [r"API_PRIVATE_KEY$", r"^TG_TOKEN$", r"^(W\d+_)?((RH|CORE)_)?PROXY$"]
# Что переносится в хранилище при импорте (секреты + данные кошельков)
VAULT_PATTERNS = SECRET_PATTERNS + [r"^W\d+_", r"^(RH|CORE)_", r"^TG_CHAT_ID$", r"^(ADDRESS|NAME)$"]


class VaultError(RuntimeError):
    pass


def is_secret(name: str) -> bool:
    return any(re.search(p, name) for p in SECRET_PATTERNS)


def belongs_in_vault(name: str) -> bool:
    return any(re.search(p, name) for p in VAULT_PATTERNS)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode())


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8"))


def _header(salt: bytes, n: int, r: int, p: int) -> dict:
    return {"format": FORMAT, "v": 1, "kdf": {"name": "scrypt", "n": n, "r": r, "p": p, "salt": _b64(salt)},
            "aead": "AES-256-GCM"}


def _aad(h: dict) -> bytes:
    # параметры шифрования защищены от подмены: они входят в проверку целостности
    return json.dumps(h, sort_keys=True, separators=(",", ":")).encode()


def _write_private(path: Path, data: bytes) -> None:
    """Атомарная запись файла, доступного только владельцу (chmod 600)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".vault-")
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


class Vault:
    def __init__(self, path: Path, key: bytes, header: dict, data: dict[str, str]):
        self.path, self._key, self._header, self.data = path, key, header, data

    @classmethod
    def create(cls, password: str, path: Path | None = None) -> "Vault":
        path = path or DEFAULT_PATH
        if path.exists():
            raise VaultError(f"Хранилище уже есть: {path}")
        salt = secrets.token_bytes(16)
        h = _header(salt, KDF_N, KDF_R, KDF_P)
        v = cls(path, _derive(password, salt, KDF_N, KDF_R, KDF_P), h, {})
        v.save()
        return v

    @classmethod
    def open(cls, password: str, path: Path | None = None) -> "Vault":
        path = path or DEFAULT_PATH
        if not path.exists():
            raise VaultError(f"Хранилища нет: {path}. Создай: python vault.py init")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            h = {k: raw[k] for k in ("format", "v", "kdf", "aead")}
            k = h["kdf"]
            if h["format"] != FORMAT or h["v"] != 1 or k["name"] != "scrypt" or h["aead"] != "AES-256-GCM":
                raise VaultError("неизвестный формат хранилища")
            if not (2 ** 14 <= k["n"] <= 2 ** 20 and 1 <= k["r"] <= 32 and 1 <= k["p"] <= 16):
                raise VaultError("подозрительные параметры хранилища")
            key = _derive(password, _unb64(k["salt"]), k["n"], k["r"], k["p"])
            plain = AESGCM(key).decrypt(_unb64(raw["nonce"]), _unb64(raw["ct"]), _aad(h))
        except InvalidTag:
            raise VaultError("Неверный пароль (или файл хранилища повреждён)") from None
        except (KeyError, ValueError, TypeError) as e:
            raise VaultError(f"Файл хранилища повреждён: {e}") from None
        return cls(path, key, h, json.loads(plain.decode("utf-8")))

    def save(self) -> None:
        nonce = secrets.token_bytes(12)
        ct = AESGCM(self._key).encrypt(nonce, json.dumps(self.data).encode("utf-8"), _aad(self._header))
        body = dict(self._header, nonce=_b64(nonce), ct=_b64(ct))
        _write_private(self.path, json.dumps(body, indent=1).encode("utf-8"))

    def change_password(self, new_password: str) -> None:
        salt = secrets.token_bytes(16)
        self._header = _header(salt, KDF_N, KDF_R, KDF_P)
        self._key = _derive(new_password, salt, KDF_N, KDF_R, KDF_P)
        self.save()


# ───────────────────────────── пароль ─────────────────────────────

def read_password(prompt: str = "Пароль хранилища: ") -> str:
    """Пароль: из файла GUARDIAN_PASSWORD_FILE (для сервера), если он есть, иначе с клавиатуры (ввод скрыт)."""
    pf = os.getenv("GUARDIAN_PASSWORD_FILE", "").strip()
    if pf and Path(pf).is_file():
        p = Path(pf)
        check_private_file(p, "файл с паролем")
        return p.read_text(encoding="utf-8").rstrip("\r\n")
    if not sys.stdin.isatty():
        if pf:
            raise VaultError(f"Нет файла с паролем {pf}, а спросить пароль негде (нет терминала)")
        raise VaultError("Нужен пароль хранилища: запусти в терминале или укажи GUARDIAN_PASSWORD_FILE")
    return getpass.getpass(prompt)


def new_password() -> str:
    while True:
        p1 = getpass.getpass(f"Новый пароль (минимум {MIN_PASSWORD} символов): ")
        if len(p1) < MIN_PASSWORD:
            print("Слишком короткий.")
            continue
        if getpass.getpass("Повтори пароль: ") != p1:
            print("Не совпадает, ещё раз.")
            continue
        return p1


def check_private_file(path: Path, what: str) -> None:
    """Предупреждаем, если файл с секретами читают другие пользователи системы."""
    if os.name != "posix" or not path.exists():
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        print(f"⚠️ {what} {path} доступен другим пользователям (права {oct(mode)}). "
              f"Исправь: chmod 600 {path}", file=sys.stderr)


def unlock(path: Path | None = None) -> Vault:
    path = path or DEFAULT_PATH
    check_private_file(path, "Хранилище")
    return Vault.open(read_password(), path)


def mask(name: str, v: str) -> str:
    """Секрет на экране: ни одного символа ключа. У прокси видно только хост и порт."""
    if not v:
        return "(пусто)"
    if name.endswith("PROXY"):
        m = re.match(r"^(\w+)://(?:[^@/]*@)?([^/@\s]+)", v)
        if m:
            return f"{m.group(1)}://{'•••@' if '@' in v else ''}{m.group(2)}"
    return f"•••• ({len(v)} симв.)"


# ───────────────────────────── импорт из .env ─────────────────────────────

def import_env(v: Vault, env_path: Path) -> list[str]:
    """Переносит данные кошельков и секреты из .env в хранилище и стирает их из .env."""
    lines = env_path.read_text(encoding="utf-8").splitlines()
    keep, moved = [], []
    for line in lines:
        m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$", line)
        if m and belongs_in_vault(m.group(1)):
            val = re.split(r"\s+#", m.group(2), maxsplit=1)[0].strip().strip('"').strip("'")
            if val:
                v.data[m.group(1)] = val
                moved.append(m.group(1))
                keep.append(f"# {m.group(1)} → перенесено в хранилище")
                continue
        keep.append(line)
    v.save()
    _write_private(env_path, ("\n".join(keep) + "\n").encode("utf-8"))
    return moved


# ───────────────────────────── командная строка ─────────────────────────────

def main(argv: list[str]) -> None:
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return
    cmd, args = argv[0], argv[1:]
    try:
        if cmd == "init":
            Vault.create(new_password())
            print(f"✅ Хранилище создано: {DEFAULT_PATH}\nНе забудь пароль — восстановить его нельзя.")
        elif cmd == "set":
            if not args:
                sys.exit("Формат: python vault.py set ИМЯ [значение]")
            name = args[0]
            v = unlock()
            val = args[1] if len(args) > 1 and not is_secret(name) else getpass.getpass(f"{name} (ввод скрыт): ")
            v.data[name] = val.strip()
            v.save()
            print(f"✅ {name} сохранено")
        elif cmd == "remove":
            v = unlock()
            for name in args:
                v.data.pop(name, None)
            v.save()
            print("✅ Удалено")
        elif cmd == "list":
            v = unlock()
            if not v.data:
                print("Хранилище пустое.")
            for k in sorted(v.data):
                print(f"{k} = {mask(k, v.data[k]) if is_secret(k) else v.data[k]}")
        elif cmd == "import":
            env_path = Path(args[0] if args else HERE / ".env")
            v = unlock()
            moved = import_env(v, env_path)
            print(f"✅ Перенесено в хранилище: {', '.join(moved) or 'ничего'}. Из {env_path} эти строки стёрты.")
        elif cmd == "passwd":
            v = unlock()
            v.change_password(new_password())
            print("✅ Пароль изменён")
        else:
            sys.exit(f"Неизвестная команда {cmd}. python vault.py help")
    except VaultError as e:
        sys.exit(f"❌ {e}")


if __name__ == "__main__":
    main(sys.argv[1:])
