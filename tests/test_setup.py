"""Тест скрипта создания ключей на симулированной бирже (без сети и без настоящего кошелька).
Запуск: python -m tests.test_setup"""
import io
import json
import os
import sys
import tempfile
import types
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
try:
    import aiohttp  # noqa: F401
except ImportError:
    sys.modules["aiohttp"] = types.SimpleNamespace(ClientTimeout=lambda **k: None)

import lighter_signer as LS  # noqa: E402
import setup_key as SK       # noqa: E402
import vault as V            # noqa: E402


class FakeLighter:
    """Имитирует REST Lighter: аккаунт, nonce, sendTx (проверяет подписи), подтверждение ключа."""
    def __init__(self):
        self.sent = []

    def get(self, url, headers=None, **p):
        if url.endswith("accountsByL1Address"):
            return {"code": 200, "sub_accounts": [{"index": 281}, {"index": 99}]}
        if url.endswith("nextNonce"):
            return {"code": 200, "nonce": 3}
        if url.endswith("orderBookDetails"):
            return {"code": 200, "order_book_details": [{"market_id": 8}, {"market_id": 3}]}
        if url.endswith("accountActiveOrders"):
            assert headers["authorization"].split(":")[1:3] == [str(p["account_index"]), "6"]
            assert p.get("market_id") == 3, p                         # проверка ключа — с номером рынка
            return {"code": 200, "orders": []}
        raise AssertionError(url)

    def post_form(self, url, form):
        info = json.loads(form["tx_info"])
        assert form["tx_type"] == "8" and info["L1Sig"] == "0xSIGNED" and info["Nonce"] == 3, info
        self.sent.append((url, info))
        return {"code": 200}


def test_setup_saves_to_vault_and_prints_no_keys():
    if not LS.signer_file()[0].exists():
        print("(пропуск: нет модуля подписи)")
        return
    tmp = Path(tempfile.mkdtemp())
    V.DEFAULT_PATH = tmp / "s.vault"
    V.Vault.create("setup password 1", V.DEFAULT_PATH)
    os.environ["GUARDIAN_PASSWORD_FILE"] = str(tmp / "pw")
    (tmp / "pw").write_text("setup password 1")
    os.chmod(tmp / "pw", 0o600)
    fake = FakeLighter()
    signed_msgs = []
    SK.Http = lambda proxy="": fake
    SK.l1_sign = lambda key, msg: signed_msgs.append((key, msg)) or "0xSIGNED"
    SK.time.sleep = lambda s: None
    sys.modules["eth_account"] = types.SimpleNamespace(
        Account=types.SimpleNamespace(from_key=lambda k: types.SimpleNamespace(address="0xWALLET")))
    SK.getpass.getpass = lambda prompt="": "0x" + "11" * 32
    sys.argv = ["setup_key.py", "--wallet", "2", "--name", "Второй", "--index", "6"]
    out = io.StringIO()
    with redirect_stdout(out):
        SK.main()
    text = out.getvalue()
    data = V.Vault.open("setup password 1", V.DEFAULT_PATH).data
    for venue in ("RH", "CORE"):
        key = data[f"W2_{venue}_API_PRIVATE_KEY"]
        assert len(key) >= 64 and key not in text                     # ключ сохранён, но не напечатан
        assert data[f"W2_{venue}_API_KEY_INDEX"] == "6"
    assert data["W2_ADDRESS"] == "0xWALLET" and data["W2_NAME"] == "Второй"
    assert "11" * 32 not in text and all(k == "11" * 32 for k, _ in signed_msgs)
    assert [u.split("/api/")[0] for u, _ in fake.sent] == ["https://api.rh.lighter.xyz",
                                                           "https://mainnet.zklighter.elliot.ai"]
    assert all(i["AccountIndex"] == 99 for _, i in fake.sent)     # основной = наименьший индекс
    assert "Register Lighter Account" in signed_msgs[0][1]
    print("✓ setup_key: ключи на RH и CORE созданы, подписаны кошельком, сохранены в хранилище, на экран не выведены")


if __name__ == "__main__":
    test_setup_saves_to_vault_and_prints_no_keys()
    print("\nТЕСТ СКРИПТА КЛЮЧЕЙ ПРОЙДЕН")
