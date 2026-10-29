"""
Минимальная обёртка над официальным модулем подписи Lighter (lighter-signer, из репозитория
elliottech/lighter-python) — без остального SDK и его ~25 зависимостей.

  • Модуль загружается только если его SHA-256 совпадает с зафиксированным (защита от подмены).
  • Модулю никогда не передаётся адрес биржи: подпись делается полностью офлайн,
    в сеть ходит только наш код и только на разрешённые адреса.
  • Скачать модуль: python fetch_signer.py
"""
from __future__ import annotations

import ctypes
import hashlib
import platform
from pathlib import Path

# Версия модуля подписи: коммит репозитория elliottech/lighter-python и SHA-256 файлов.
SIGNER_COMMIT = "5825eb19867a4dbdd47c02642dc1eec30c30ca73"
SIGNER_FILES = {
    ("Linux", "x86_64"): ("lighter-signer-linux-amd64.so",
                          "49c6b61e0e95a4a70f2a252e469c393760c929d61179c340e2932ab62882caf2"),
    ("Linux", "arm64"): ("lighter-signer-linux-arm64.so",
                         "3b6fd0b8f4caecbff9ce817dffb11a2321f078e0b4acc9a58623354bb55cc289"),
    ("Darwin", "x86_64"): ("lighter-signer-darwin-amd64.dylib",
                           "a74e230cebde6c61d35de09587f0980b383b991fa694f974b4070adec6b64bb3"),
    ("Darwin", "arm64"): ("lighter-signer-darwin-arm64.dylib",
                          "b8e602542721a11aff4236a247e775150b421c0eb7532442209658a5b0c22f31"),
    ("Windows", "x86_64"): ("lighter-signer-windows-amd64.dll",
                            "3f6baac6015a27d652971947442c69f26f37cf6bdae7fd74f3c05cd2d8c194b1"),
}
SIGNER_DIR = Path(__file__).resolve().parent / "signers"

# Модулю нужен «адрес» только для CheckClient (проверки ключа по сети), который мы не вызываем.
# Даём заведомо недоступный локальный адрес, чтобы модуль физически не мог никуда обратиться.
NO_NETWORK_URL = b"http://127.0.0.1:9"

ORDER_TYPE_MARKET = 1
TIF_IOC = 0


class _ApiKeyResponse(ctypes.Structure):
    _fields_ = [("privateKey", ctypes.c_void_p), ("publicKey", ctypes.c_void_p), ("err", ctypes.c_void_p)]


class _StrOrErr(ctypes.Structure):
    _fields_ = [("str", ctypes.c_void_p), ("err", ctypes.c_void_p)]


class _SignedTx(ctypes.Structure):
    _fields_ = [("txType", ctypes.c_uint8), ("txInfo", ctypes.c_void_p), ("txHash", ctypes.c_void_p),
                ("messageToSign", ctypes.c_void_p), ("err", ctypes.c_void_p)]


class SignerError(RuntimeError):
    pass


def platform_key() -> tuple[str, str]:
    system = platform.system()
    machine = platform.machine().lower()
    arch = "x86_64" if machine in ("x86_64", "amd64") else "arm64" if machine in ("arm64", "aarch64") else machine
    return system, arch


def signer_file() -> tuple[Path, str]:
    key = platform_key()
    if key not in SIGNER_FILES:
        raise SignerError(f"Модуль подписи Lighter не поддерживает {key[0]}/{key[1]}")
    name, sha = SIGNER_FILES[key]
    return SIGNER_DIR / name, sha


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


_lib = None


def load() -> ctypes.CDLL:
    """Загружает модуль подписи после проверки SHA-256."""
    global _lib
    if _lib is not None:
        return _lib
    path, expected = signer_file()
    if not path.exists():
        raise SignerError(f"Нет модуля подписи {path.name}. Скачай его: python fetch_signer.py")
    actual = sha256_file(path)
    if actual != expected:
        raise SignerError(f"Модуль подписи {path.name} не совпадает с эталоном (SHA-256 {actual}). "
                          "Файл повреждён или подменён — удали его и скачай заново: python fetch_signer.py")
    lib = ctypes.CDLL(str(path))
    lib.GenerateAPIKey.argtypes, lib.GenerateAPIKey.restype = [], _ApiKeyResponse
    lib.CreateClient.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_longlong]
    lib.CreateClient.restype = ctypes.c_void_p
    lib.SignCreateOrder.argtypes = [ctypes.c_longlong, ctypes.c_longlong, ctypes.c_longlong, ctypes.c_int,
                                    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                    ctypes.c_longlong, ctypes.c_longlong, ctypes.c_int, ctypes.c_int,
                                    ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_longlong,
                                    ctypes.c_int, ctypes.c_longlong]
    lib.SignCreateOrder.restype = _SignedTx
    lib.SignCancelOrder.argtypes = [ctypes.c_longlong, ctypes.c_longlong, ctypes.c_uint8, ctypes.c_longlong,
                                    ctypes.c_int, ctypes.c_longlong]
    lib.SignCancelOrder.restype = _SignedTx
    lib.SignChangePubKey.argtypes = [ctypes.c_char_p, ctypes.c_uint8, ctypes.c_longlong, ctypes.c_int,
                                     ctypes.c_longlong]
    lib.SignChangePubKey.restype = _SignedTx
    lib.CreateAuthToken.argtypes = [ctypes.c_longlong, ctypes.c_int, ctypes.c_longlong]
    lib.CreateAuthToken.restype = _StrOrErr
    lib.Free.argtypes, lib.Free.restype = [ctypes.c_void_p], None
    _lib = lib
    return lib


def _take(ptr) -> str | None:
    """Читает строку, выделенную модулем, и освобождает её его же функцией Free."""
    if not ptr:
        return None
    try:
        v = ctypes.cast(ptr, ctypes.c_char_p).value
        return v.decode("utf-8") if v is not None else None
    finally:
        _lib.Free(ptr)


def _tx(res: _SignedTx) -> tuple[int, str, str, str]:
    err = _take(res.err)
    info = _take(res.txInfo)
    tx_hash = _take(res.txHash)
    msg = _take(res.messageToSign)
    if err:
        raise SignerError(err)
    return int(res.txType), info, tx_hash, msg or ""


def generate_api_key() -> tuple[str, str]:
    """Новая пара ключей API: (приватный, публичный). Генерируется локально."""
    lib = load()
    r = lib.GenerateAPIKey()
    priv, pub, err = _take(r.privateKey), _take(r.publicKey), _take(r.err)
    if err:
        raise SignerError(err)
    return priv, pub


class Signer:
    """Подписывает транзакции одним API-ключом одного аккаунта. Полностью офлайн."""

    def __init__(self, account_index: int, api_key_index: int, api_private_key: str, chain_id: int):
        self.lib = load()
        self.account_index = int(account_index)
        self.api_key_index = int(api_key_index)
        key = api_private_key[2:] if api_private_key.startswith("0x") else api_private_key
        err = _take(self.lib.CreateClient(NO_NETWORK_URL, key.encode("utf-8"), int(chain_id),
                                          self.api_key_index, self.account_index))
        del key
        if err:
            raise SignerError(err)

    def auth_token(self, deadline_unix: int) -> str:
        r = self.lib.CreateAuthToken(int(deadline_unix), self.api_key_index, self.account_index)
        token, err = _take(r.str), _take(r.err)
        if err:
            raise SignerError(err)
        return token

    def market_order(self, market_index: int, client_order_index: int, base_amount: int, price: int,
                     is_ask: bool, reduce_only: bool, nonce: int) -> tuple[int, str]:
        """Рыночная IOC-заявка. price — худшая допустимая цена (целое, в шагах цены рынка)."""
        tx_type, info, _, _ = _tx(self.lib.SignCreateOrder(
            int(market_index), int(client_order_index), int(base_amount), int(price), int(bool(is_ask)),
            ORDER_TYPE_MARKET, TIF_IOC, int(bool(reduce_only)), 0, 0,       # trigger 0, expiry 0 (IOC)
            0, 0, 0, 0, 0,                                                     # без интегратора, self-trade по умолч.
            0, int(nonce), self.api_key_index, self.account_index))
        return tx_type, info

    def cancel_order(self, market_index: int, order_index: int, nonce: int) -> tuple[int, str]:
        tx_type, info, _, _ = _tx(self.lib.SignCancelOrder(int(market_index), int(order_index), 0, int(nonce),
                                                           self.api_key_index, self.account_index))
        return tx_type, info

    def change_pub_key(self, new_pub_key: str, nonce: int) -> tuple[int, str, str]:
        """Регистрация API-ключа. Возвращает (tx_type, tx_info, сообщение для подписи кошельком)."""
        tx_type, info, _, msg = _tx(self.lib.SignChangePubKey(new_pub_key.encode("utf-8"), 0, int(nonce),
                                                              self.api_key_index, self.account_index))
        return tx_type, info, msg
