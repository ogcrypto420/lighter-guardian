"""Тесты безопасности: хранилище, вымарывание секретов, белый список адресов, уровни подробности,
проверка модуля подписи, формат транзакций.  Запуск: python -m tests.test_security"""
import asyncio
import io
import json
import logging
import os
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
try:
    import aiohttp  # noqa: F401
except ImportError:   # для тестов без установленных зависимостей
    import types
    sys.modules["aiohttp"] = types.SimpleNamespace(ClientTimeout=lambda **k: None)

import security as SEC  # noqa: E402
import vault as V       # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="guardian-test-"))


def test_vault_roundtrip_and_tamper():
    path = TMP / "a.vault"
    v = V.Vault.create("correct horse battery", path)
    v.data.update({"W1_RH_API_PRIVATE_KEY": "deadbeef" * 10, "W1_ADDRESS": "0xabc"})
    v.save()
    raw = path.read_text()
    assert "deadbeef" not in raw and "0xabc" not in raw                     # на диске только шифр
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600                   # файл только для владельца
    assert V.Vault.open("correct horse battery", path).data["W1_ADDRESS"] == "0xabc"
    try:
        V.Vault.open("wrong password!!", path)
        raise AssertionError("открылось с неверным паролем")
    except V.VaultError as e:
        assert "Неверный пароль" in str(e)
    # подмена шифртекста
    d = json.loads(raw)
    ct = bytearray(V._unb64(d["ct"]))
    ct[5] ^= 1
    d["ct"] = V._b64(bytes(ct))
    path.write_text(json.dumps(d))
    try:
        V.Vault.open("correct horse battery", path)
        raise AssertionError("испорченный файл открылся")
    except V.VaultError:
        pass
    # подмена параметров шифрования (они защищены проверкой целостности)
    d = json.loads(raw)
    d["kdf"]["n"] = 2 ** 15
    path.write_text(json.dumps(d))
    try:
        V.Vault.open("correct horse battery", path)
        raise AssertionError("подменённые параметры приняты")
    except V.VaultError:
        pass
    print("1. хранилище: на диске только шифр, права 600, неверный пароль и подмена не проходят ✓")


def test_vault_import_wipes_env():
    path = TMP / "b.vault"
    v = V.Vault.create("another long password", path)
    env = TMP / ".env"
    env.write_text("DRY_RUN=true\nW1_ADDRESS=0x111\nW1_RH_API_PRIVATE_KEY=abcdef123456  # ключ\n"
                   "TG_TOKEN=123:ABCDEF\nPROXY=http://u:p@h:1\nSOFT_STOP=act\nTG_CHAT_ID=42\n")
    moved = V.import_env(v, env)
    left = env.read_text()
    assert set(moved) == {"W1_ADDRESS", "W1_RH_API_PRIVATE_KEY", "TG_TOKEN", "PROXY", "TG_CHAT_ID"}
    assert "abcdef123456" not in left and "123:ABCDEF" not in left and "u:p@" not in left
    assert "DRY_RUN=true" in left and "SOFT_STOP=act" in left                # настройки остались
    assert V.Vault.open("another long password", path).data["W1_RH_API_PRIVATE_KEY"] == "abcdef123456"
    assert V.is_secret("W2_CORE_PROXY") and V.is_secret("TG_TOKEN") and not V.is_secret("HTTPS_PROXY")
    print("2. импорт из .env: секреты переехали в хранилище и стёрты из файла ✓")


def test_redaction_logs_and_messages():
    key = "0x" + "a1b2c3d4" * 8
    SEC.register_secret(key)
    SEC.register_secret("7012345678:AAFakeTelegramToken")
    SEC.register_secret("http://user9:SuperSecret@1.2.3.4:8080")
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    lg = logging.getLogger("redact-test")
    lg.addHandler(h)
    lg.addFilter(SEC.RedactingFilter())
    lg.warning("ключ %s токен %s прокси %s", key, "https://api.telegram.org/bot7012345678:AAFakeTelegramToken/x",
               "http://user9:SuperSecret@1.2.3.4:8080")
    try:
        raise RuntimeError(f"сбой с ключом {key[2:]}")
    except RuntimeError:
        lg.exception("ошибка")
    out = buf.getvalue()
    for leak in ("a1b2c3d4", "AAFakeTelegramToken", "SuperSecret", "user9"):
        assert leak not in out, (leak, out)
    tok = "1792108590:12345:4:b9dd963a121624a6e368c0ffee"
    assert "b9dd963a" not in SEC.redact(f"auth {tok}")
    print("3. ключи, токены и пароли прокси вымарываются из логов, ошибок и сообщений ✓")


def test_allowlist():
    calls = []

    class Raw:
        def get(self, url, **kw):
            calls.append(url)
            return "ok"
        post = ws_connect = get

    s = SEC.SafeSession(Raw(), {"api.rh.lighter.xyz", "api.telegram.org"})
    assert s.get("https://api.rh.lighter.xyz/api/v1/account") == "ok"
    assert s.ws_connect("wss://api.rh.lighter.xyz/stream") == "ok"
    for bad in ("https://evil.example.com/steal", "http://api.rh.lighter.xyz/api/v1/x",
                "https://api.rh.lighter.xyz.evil.com/", "https://api.telegram.org@evil.com/"):
        try:
            s.post(bad)
            raise AssertionError(f"пропущен {bad}")
        except SEC.BlockedHost:
            pass
    assert len(calls) == 2
    import guardian as G
    assert G.ALLOWED_HOSTS == {"api.rh.lighter.xyz", "api.rh-testnet.lighter.xyz", "mainnet.zklighter.elliot.ai",
                               "testnet.zklighter.elliot.ai", "api.telegram.org"}, G.ALLOWED_HOSTS
    print("4. белый список: только Lighter и Telegram по https/wss, обходные адреса блокируются ✓")


def test_detail_levels():
    from security import S, T, render
    msg = f"🚨 {T('NVDA')} · #1 RH: лонг {S('2.5')} по {S('217.94')}"
    assert render(msg, "full") == "🚨 NVDA · #1 RH: лонг 2.5 по 217.94"
    assert render(msg, "short") == "🚨 NVDA · #1 RH: лонг ••• по •••"
    assert render(msg, "minimal") == "🚨 ••• · #1 RH: лонг ••• по •••"

    import guardian as G
    sent = []

    class Raw:
        def post(self, url, json=None, **kw):
            sent.append(json)

            class R:
                async def __aenter__(s): return s
                async def __aexit__(s, *a): pass
                async def json(s, **k): return {"ok": True}
                async def text(s): return '{"ok": true}'
            return R()
    tg = G.Telegram(Raw(), "123:tok", "42", detail="short")
    asyncio.run(tg.send(msg))
    assert sent[0]["text"] == "🚨 NVDA · #1 RH: лонг ••• по •••"
    print("5. Telegram: full / short / minimal — цифры и тикеры скрываются ✓")


def test_signer_hash_check():
    import lighter_signer as LS
    path, sha = LS.signer_file()
    if not path.exists():
        print("6. (пропуск: модуль подписи не скачан — python fetch_signer.py)")
        return
    assert LS.sha256_file(path) == sha
    fake_dir = TMP / "signers"
    fake_dir.mkdir()
    (fake_dir / path.name).write_bytes(b"\x7fELF not really")
    old_dir, old_lib = LS.SIGNER_DIR, LS._lib
    LS.SIGNER_DIR, LS._lib = fake_dir, None
    try:
        LS.load()
        raise AssertionError("подменённый модуль загрузился")
    except LS.SignerError as e:
        assert "подменён" in str(e)
    finally:
        LS.SIGNER_DIR, LS._lib = old_dir, old_lib
    print("6. подменённый модуль подписи не загружается (проверка SHA-256) ✓")


def test_send_tx_format_and_nonce_retry():
    import lighter_signer as LS
    import guardian as G
    if not LS.signer_file()[0].exists():
        print("7. (пропуск: нет модуля подписи)")
        return
    priv, _ = LS.generate_api_key()
    posts, nonces = [], iter([10, 11])
    replies = iter([{"code": 21104, "message": "invalid nonce"}, {"code": 200, "tx_hash": "0xabc"}])

    class R:
        def __init__(s, data, status=200): s.data, s.status = data, status
        async def __aenter__(s): return s
        async def __aexit__(s, *a): pass
        async def json(s, **k): return s.data
        async def text(s): return json.dumps(s.data)

    class Http:
        def get(self, url, params=None, **kw):
            assert url.endswith("/api/v1/nextNonce") and params == {"account_index": 7, "api_key_index": 5}
            return R({"code": 200, "nonce": next(nonces)})

        def post(self, url, data=None, **kw):
            posts.append((url, data, kw.get("proxy")))
            return R(next(replies))

    ex = G.LighterExchange(Http(), "robinhood", 7, 5, priv, proxy="http://u:p@1.1.1.1:1")
    ex.signer = LS.Signer(7, 5, priv, 466324)
    ex.markets = {15: G.Market(15, "NVDA", 4, 2)}
    ok, err = asyncio.run(ex.market_close(15, 2.5, is_ask=True, worst_price=207.364))
    assert ok, err
    assert len(posts) == 2                                     # первый nonce отвергнут → повтор со свежим
    url, form, proxy = posts[1]
    assert url == "https://api.rh.lighter.xyz/api/v1/sendTx" and proxy == "http://u:p@1.1.1.1:1"
    assert set(form) == {"tx_type", "tx_info"} and form["tx_type"] == "14"   # как в официальном SDK
    info = json.loads(form["tx_info"])
    assert (info["Nonce"], info["BaseAmount"], info["Price"], info["IsAsk"], info["ReduceOnly"],
            info["Type"], info["TimeInForce"]) == (11, 25000, 20736, 1, 1, 1, 0), info
    assert priv not in form["tx_info"]                         # ключ в транзакцию не попадает
    print("7. транзакция: формат как в SDK, reduce-only IOC, цена округлена в безопасную сторону, "
          "повтор при неверном nonce, ключ не уходит ✓")


def test_plaintext_secrets_refused():
    import guardian as G
    os.environ["W9_RH_API_PRIVATE_KEY"] = "plain-text-key"
    os.environ.pop("ALLOW_PLAINTEXT_SECRETS", None)
    try:
        G.load_secrets()
        raise AssertionError("запустился с ключом открытым текстом")
    except SystemExit as e:
        assert "открытым текстом" in str(e) and "W9_RH_API_PRIVATE_KEY" in str(e)
    finally:
        del os.environ["W9_RH_API_PRIVATE_KEY"]
    print("8. ключи открытым текстом в .env — страж отказывается запускаться ✓")


def test_hardening():
    import subprocess
    code = ("import resource, security; d = security.harden_process(); "
            "assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0) and d; print(len(d))")
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    print("9. дампы памяти отключены, файлы создаются только для владельца ✓")


def test_vault_cli_with_password_file():
    import subprocess
    vp = TMP / "cli.vault"
    v = V.Vault.create("cli password 123", vp)
    v.data.update({"W1_RH_API_PRIVATE_KEY": "f00dfeed" * 8, "W1_ADDRESS": "0xAbC", "TG_CHAT_ID": "42"})
    v.save()
    pw = TMP / "pw.txt"
    pw.write_text("cli password 123\n")
    os.chmod(pw, 0o600)
    envv = dict(os.environ, GUARDIAN_VAULT=str(vp), GUARDIAN_PASSWORD_FILE=str(pw))
    r = subprocess.run([sys.executable, "vault.py", "list"], cwd=ROOT, env=envv, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "W1_ADDRESS = 0xAbC" in r.stdout and "f00d" not in r.stdout, r.stdout
    assert "W1_RH_API_PRIVATE_KEY = •••• (64 симв.)" in r.stdout, r.stdout
    assert V.mask("W2_PROXY", "http://user:pa55word@1.2.3.4:8080") == "http://•••@1.2.3.4:8080"
    pw.write_text("wrong password!!\n")
    r = subprocess.run([sys.executable, "vault.py", "list"], cwd=ROOT, env=envv, capture_output=True, text=True)
    assert r.returncode != 0 and "Неверный пароль" in (r.stderr + r.stdout)
    print("10. vault.py list: значения ключей скрыты, неверный пароль — отказ ✓")


def test_missing_password_file():
    import subprocess
    vp = TMP / "nopw.vault"
    V.Vault.create("nopw password 1", vp)
    envv = dict(os.environ, GUARDIAN_VAULT=str(vp), GUARDIAN_PASSWORD_FILE=str(TMP / "нет-такого.txt"))
    r = subprocess.run([sys.executable, "vault.py", "list"], cwd=ROOT, env=envv, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True)
    out = r.stderr + r.stdout
    assert r.returncode != 0 and "Нет файла с паролем" in out and "Traceback" not in out, out
    print("11. нет файла с паролем и нет терминала — понятная ошибка, без падения ✓")


def test_wallet_from_site():
    k = "ab" * 40
    e = V.wallet_entries(2, "Мобильный", "0x" + "12" * 20,
                         {"RH": {"key": k, "index": "5", "account": ""}, "CORE": {"key": "0x" + k, "index": "4",
                                                                                  "account": "77"}})
    assert e["W2_RH_API_PRIVATE_KEY"] == "0x" + k and e["W2_RH_API_KEY_INDEX"] == "5"
    assert "W2_RH_ACCOUNT_INDEX" not in e and e["W2_CORE_ACCOUNT_INDEX"] == "77" and e["W2_NAME"] == "Мобильный"
    for bad in ({"RH": {"key": k, "index": "2"}}, {"RH": {"key": "xyz", "index": "4"}}, {}):
        try:
            V.wallet_entries(2, "", "0x" + "12" * 20, bad)
            raise AssertionError(bad)
        except V.VaultError:
            pass
    # страж видит такой кошелёк
    import guardian as G
    G.SECRETS.clear(); G.SECRETS.update(e)
    w = G.wallet_configs()
    G.SECRETS.clear()
    assert [(x["wallet"], [c["network"] for c in x["exchanges"]]) for x in w] == [(2, ["robinhood", "mainnet"])]
    print("12. ключи с сайта Lighter: проверка формата и индекса, страж видит кошелёк ✓")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
    print("\nВСЕ ТЕСТЫ БЕЗОПАСНОСТИ ПРОЙДЕНЫ")
