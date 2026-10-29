#!/usr/bin/env python3
"""
Создание API-ключей Lighter для стража — для одного кошелька сразу на RH и на основном Lighter (CORE).
Ключи сохраняются прямо в зашифрованное хранилище и на экран не выводятся.

ЗАПУСКАЙ ТОЛЬКО У СЕБЯ НА КОМПЬЮТЕРЕ. Приватный ключ кошелька нужен один раз — чтобы подписать
регистрацию API-ключей. Он не сохраняется и в сеть не уходит: уходит только подпись.

    python setup_key.py --wallet 1 --name Основной
    python setup_key.py --wallet 2 --proxy http://логин:пароль@хост:порт
    python setup_key.py --wallet 3 --only rh
    python setup_key.py --wallet 1 --testnet

Индекс ключа: 4–156 или 158–254 (0–3 и 157 заняты приложениями Lighter). Выбери индекс, который ты больше
нигде не используешь — старый ключ с этим индексом перестанет работать.
"""
import argparse
import getpass
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlsplit

import vault
from guardian import NETWORKS, mask_proxy
from lighter_signer import Signer, generate_api_key
from security import harden_process

LIGHTER_HOSTS = {urlsplit(n[0]).hostname for n in NETWORKS.values()}


class Http:
    """Простые HTTPS-запросы только к Lighter, через прокси кошелька (если задан). Системный прокси не используется."""

    def __init__(self, proxy: str = ""):
        handler = urllib.request.ProxyHandler({"https": proxy} if proxy else {})
        self.opener = urllib.request.build_opener(handler)

    def _check(self, url: str):
        u = urlsplit(url)
        if u.scheme != "https" or u.hostname not in LIGHTER_HOSTS:
            raise RuntimeError(f"Заблокировано обращение к {u.hostname}")

    def get(self, url: str, headers: dict | None = None, **params) -> dict:
        self._check(url)
        req = urllib.request.Request(url + "?" + urllib.parse.urlencode(params), headers=headers or {})
        return self._do(req)

    def post_form(self, url: str, form: dict) -> dict:
        self._check(url)
        req = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode(), method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded",
                                              "Accept": "application/json"})
        return self._do(req)

    def _do(self, req) -> dict:
        try:
            with self.opener.open(req, timeout=30) as r:
                return json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read().decode() or "{}") | {"_http": e.code}
            except Exception:  # noqa: BLE001
                return {"_http": e.code}


def l1_sign(eth_key: str, message: str) -> str:
    """Подпись кошельком (EIP-191, как в официальном SDK Lighter)."""
    from eth_account import Account
    from eth_account.messages import encode_defunct
    signed = Account.from_key(eth_key).sign_message(encode_defunct(text=message))
    return "0x" + bytes(signed.signature).hex()


def register(http: Http, network: str, eth_key: str, address: str, index: int, account: int | None):
    """Регистрирует новый API-ключ на одной бирже. Возвращает (account_index, private_key)."""
    api, _, chain_id, label = NETWORKS[network]
    if account is None:
        data = http.get(f"{api}/api/v1/accountsByL1Address", l1_address=address)
        subs = sorted(data.get("sub_accounts") or [], key=lambda s: int(s["index"]))
        if not subs:
            raise RuntimeError(f"на {label} нет аккаунта для этого адреса — сначала сделай там депозит")
        account = int(subs[0]["index"])
        if len(subs) > 1:
            print(f"  {label}: несколько аккаунтов ({', '.join(str(s['index']) for s in subs)}), "
                  f"беру основной {account}")
    priv, pub = generate_api_key()                   # пара ключей создаётся локально
    signer = Signer(account, index, priv, chain_id)  # подпись — локально, без сети
    nonce = int(http.get(f"{api}/api/v1/nextNonce", account_index=account, api_key_index=index)["nonce"])
    tx_type, tx_info, msg = signer.change_pub_key(pub, nonce)
    info = json.loads(tx_info)
    info["L1Sig"] = l1_sign(eth_key, msg)
    resp = http.post_form(f"{api}/api/v1/sendTx", {"tx_type": str(tx_type), "tx_info": json.dumps(info)})
    if int(resp.get("code", resp.get("_http", 0))) != 200:
        raise RuntimeError(f"регистрация не прошла: {resp.get('message') or resp}")
    print(f"  {label}: ключ отправлен, жду подтверждения…")
    token = signer.auth_token(int(time.time()) + 600)
    mk = http.get(f"{api}/api/v1/orderBookDetails", filter="perp").get("order_book_details") or []
    extra = {"market_id": min(int(m["market_id"]) for m in mk)} if mk else {}
    for _ in range(12):
        time.sleep(5)
        r = http.get(f"{api}/api/v1/accountActiveOrders", headers={"authorization": token}, account_index=account,
                     **extra)
        if int(r.get("code", r.get("_http", 0))) == 200:
            return account, priv
    raise RuntimeError("ключ не подтвердился за минуту, попробуй позже")


def main() -> None:
    ap = argparse.ArgumentParser(description="Создать API-ключи Lighter для стража")
    ap.add_argument("--wallet", type=int, default=1, help="номер кошелька в страже (1, 2, 3…)")
    ap.add_argument("--name", default="", help="подпись кошелька в сообщениях, например «Основной»")
    ap.add_argument("--only", choices=["rh", "core"], help="только одна биржа")
    ap.add_argument("--testnet", action="store_true", help="тестнеты вместо основных сетей")
    ap.add_argument("--index", type=int, default=4, help="индекс API-ключа (по умолчанию 4)")
    ap.add_argument("--rh-account", type=int, default=None, help="account index на RH, если нужен субаккаунт")
    ap.add_argument("--core-account", type=int, default=None, help="account index на CORE, если нужен субаккаунт")
    ap.add_argument("--proxy", default=None, help="прокси для этого кошелька: http://логин:пароль@хост:порт")
    args = ap.parse_args()

    if args.index in (0, 1, 2, 3, 157, 255) or not 0 <= args.index <= 254:
        sys.exit("Этот индекс занят приложениями Lighter. Возьми 4–156 или 158–254.")
    if args.wallet < 1:
        sys.exit("Номер кошелька — 1, 2, 3…")
    harden_process()

    try:
        v = vault.unlock()
    except vault.VaultError as e:
        sys.exit(f"❌ {e}")
    w = f"W{args.wallet}_"
    proxy = args.proxy if args.proxy is not None else (v.data.get(f"{w}PROXY") or v.data.get("PROXY") or "")

    venues = []
    if args.only != "core":
        venues.append(("RH", "robinhood_testnet" if args.testnet else "robinhood", args.rh_account))
    if args.only != "rh":
        venues.append(("CORE", "testnet" if args.testnet else "mainnet", args.core_account))

    print(f"\nКошелёк #{args.wallet}: {', '.join(x for x, _, _ in venues)} · индекс ключа {args.index}"
          + (f" · прокси {mask_proxy(proxy)}" if proxy else ""))
    print("Вставь приватный ключ кошелька (ввод скрыт, не сохраняется):")
    eth_key = getpass.getpass("> ").strip()
    if eth_key.startswith("0x"):
        eth_key = eth_key[2:]
    from eth_account import Account
    address = Account.from_key(eth_key).address
    print(f"Адрес: {address}\n")

    http = Http(proxy)
    ok = 0
    try:
        for venue, network, account in venues:
            try:
                acc, priv = register(http, network, eth_key, address, args.index, account)
            except Exception as e:  # noqa: BLE001
                print(f"  ❌ {venue}: {e}")
                continue
            p = f"{w}{venue}_"
            v.data[f"{p}API_KEY_INDEX"] = str(args.index)
            v.data[f"{p}API_PRIVATE_KEY"] = priv
            if account is not None:
                v.data[f"{p}ACCOUNT_INDEX"] = str(acc)
            if args.testnet:
                v.data[f"{p}NETWORK"] = network
            del priv
            ok += 1
            print(f"  ✅ {venue}: ключ создан и сохранён в хранилище (аккаунт {acc})")
    finally:
        eth_key = None  # noqa: F841

    if not ok:
        sys.exit("\nНи один ключ не создан.")
    v.data[f"{w}ADDRESS"] = address
    if args.name:
        v.data[f"{w}NAME"] = args.name
    if args.proxy:
        v.data[f"{w}PROXY"] = args.proxy
    v.save()
    print(f"\n✅ Кошелёк #{args.wallet} записан в хранилище. Ключи на экран не выводились.")
    print("Отозвать ключ — запусти скрипт снова с тем же --index (старый ключ перестанет работать).")


if __name__ == "__main__":
    main()
