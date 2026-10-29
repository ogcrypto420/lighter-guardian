#!/usr/bin/env python3
"""
Создание API-ключей Lighter для стража — для одного кошелька сразу на RH и на основном Lighter (CORE).

ЗАПУСКАЙ ТОЛЬКО У СЕБЯ НА КОМПЬЮТЕРЕ. Приватный ключ кошелька нужен один раз — чтобы подписать
регистрацию API-ключей. Скрипт его никуда не сохраняет и не отправляет (уходит только подпись).

    python setup_key.py --wallet 1                  # RH и CORE, кошелёк №1
    python setup_key.py --wallet 2 --only rh        # только RH для кошелька №2
    python setup_key.py --wallet 1 --testnet        # тестнеты RH и CORE

Индекс ключа: 4–156 или 158–254 (0–3 и 157 заняты приложениями Lighter). Выбери индекс, который ты больше
нигде не используешь — старый ключ с этим индексом перестанет работать.
"""
import argparse
import asyncio
import getpass
import os
import sys

from guardian import NETWORKS, mask_proxy  # заодно подхватывает .env


async def register(lighter, network: str, eth_key: str, address: str, index: int, account: int | None,
                   proxy: str = ""):
    """Регистрирует новый API-ключ на одной бирже. Возвращает (account_index, private_key) или бросает ошибку."""
    api_url, _, chain_id, label = NETWORKS[network]
    conf = lighter.Configuration(host=api_url)
    if proxy:
        conf.proxy = proxy
    api = lighter.ApiClient(configuration=conf)
    try:
        if account is None:
            try:
                resp = await lighter.AccountApi(api).accounts_by_l1_address(l1_address=address)
                subs = sorted(resp.sub_accounts, key=lambda s: int(s.index))
            except Exception:  # noqa: BLE001
                subs = []
            if not subs:
                raise RuntimeError(f"на {label} нет аккаунта для {address} — сначала сделай там депозит")
            account = int(subs[0].index)
            if len(subs) > 1:
                print(f"  {label}: несколько аккаунтов ({', '.join(str(s.index) for s in subs)}), "
                      f"беру основной {account}")
        priv, pub, err = lighter.create_api_key()
        if err:
            raise RuntimeError(f"не удалось сгенерировать ключ: {err}")
        client = lighter.SignerClient(url=api_url, account_index=account,
                                      api_private_keys={index: priv}, chain_id=chain_id)
        if proxy:
            client.api_client.configuration.proxy = proxy
            client.api_client.rest_client.proxy = proxy
        # nonce берём через Python-клиент SDK (он учитывает PROXY), а не внутри модуля подписи
        nonce = (await lighter.TransactionApi(api).next_nonce(account_index=account, api_key_index=index)).nonce
        _, err = await client.change_api_key(eth_private_key=eth_key, new_pubkey=pub, nonce=nonce,
                                             api_key_index=index)
        if err:
            raise RuntimeError(f"регистрация не прошла: {err}")
        print(f"  {label}: ключ отправлен, жду подтверждения…")
        token, _ = client.create_auth_token_with_expiry(600, api_key_index=index)
        orders_api = lighter.OrderApi(api)
        for _ in range(12):
            await asyncio.sleep(5)
            try:
                await orders_api.account_active_orders(authorization=token, account_index=account)
                break
            except Exception:  # noqa: BLE001
                continue
        else:
            raise RuntimeError("ключ не подтвердился за минуту, попробуй позже")
        await client.close()
        return account, priv
    finally:
        await api.close()


async def main() -> None:
    ap = argparse.ArgumentParser(description="Создать API-ключи Lighter для стража")
    ap.add_argument("--wallet", type=int, default=1, help="номер кошелька в стражe (1, 2, 3…)")
    ap.add_argument("--name", default="", help="подпись кошелька в сообщениях, например «Основной»")
    ap.add_argument("--only", choices=["rh", "core"], help="только одна биржа")
    ap.add_argument("--testnet", action="store_true", help="тестнеты вместо основных сетей")
    ap.add_argument("--index", type=int, default=4, help="индекс API-ключа (по умолчанию 4)")
    ap.add_argument("--rh-account", type=int, default=None, help="account index на RH, если нужен субаккаунт")
    ap.add_argument("--core-account", type=int, default=None, help="account index на CORE, если нужен субаккаунт")
    ap.add_argument("--proxy", default=None, help="прокси для этого кошелька: http://логин:пароль@хост:порт")
    args = ap.parse_args()
    proxy = args.proxy if args.proxy is not None else (os.getenv(f"W{args.wallet}_PROXY") or os.getenv("PROXY") or "")

    if args.index in (0, 1, 2, 3, 157, 255) or not 0 <= args.index <= 254:
        sys.exit("Этот индекс занят приложениями Lighter. Возьми 4–156 или 158–254.")
    if args.wallet < 1:
        sys.exit("Номер кошелька — 1, 2, 3…")

    import eth_account
    import lighter

    venues = []
    if args.only != "core":
        venues.append(("RH", "robinhood_testnet" if args.testnet else "robinhood", args.rh_account))
    if args.only != "rh":
        venues.append(("CORE", "testnet" if args.testnet else "mainnet", args.core_account))

    print(f"\nКошелёк #{args.wallet}: {', '.join(v for v, _, _ in venues)} · индекс ключа {args.index}"
          + (f" · прокси {mask_proxy(proxy)}" if proxy else ""))
    print("Вставь приватный ключ кошелька (ввод скрыт, никуда не сохраняется):")
    eth_key = getpass.getpass("> ").strip()
    if eth_key.startswith("0x"):
        eth_key = eth_key[2:]
    address = eth_account.Account.from_key(eth_key).address
    print(f"Адрес: {address}\n")

    w = f"W{args.wallet}_"
    lines = [f"{w}ADDRESS={address}"]
    if args.name:
        lines.append(f"{w}NAME={args.name}")
    if args.proxy:
        lines.append(f"{w}PROXY={args.proxy}")
    failed = []
    try:
        for venue, network, account in venues:
            try:
                acc, priv = await register(lighter, network, eth_key, address, args.index, account, proxy)
            except Exception as e:  # noqa: BLE001
                failed.append(f"{venue}: {e}")
                print(f"  ❌ {venue}: {e}")
                continue
            print(f"  ✅ {venue}: готово (аккаунт {acc})")
            if args.testnet:
                lines.append(f"{w}{venue}_NETWORK={network}")
            if account is not None:
                lines.append(f"{w}{venue}_ACCOUNT_INDEX={acc}")
            lines.append(f"{w}{venue}_API_KEY_INDEX={args.index}")
            lines.append(f"{w}{venue}_API_PRIVATE_KEY={priv}")
    finally:
        eth_key = None  # noqa: F841

    if len(failed) == len(venues):
        sys.exit("\nНи один ключ не создан.")
    print("\nВпиши в .env (или в настройки сервера):\n")
    print("\n".join(lines))
    print("\nAPI-ключ может торговать, но вывести деньги им можно только обратно на твой же кошелёк.")
    print("Не публикуй его. Отозвать — запусти скрипт снова с тем же --index (старый ключ перестанет работать).")


if __name__ == "__main__":
    asyncio.run(main())
