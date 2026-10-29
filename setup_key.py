#!/usr/bin/env python3
"""
Создание отдельного API-ключа Lighter для стража.

ЗАПУСКАЙ ТОЛЬКО У СЕБЯ НА КОМПЬЮТЕРЕ. Приватный ключ кошелька нужен один раз — чтобы подписать
регистрацию нового API-ключа. Скрипт его никуда не сохраняет и не отправляет (уходит только подпись).

    python setup_key.py --network robinhood --index 4

Сеть: robinhood (Lighter RH), mainnet (основной Lighter), robinhood_testnet, testnet.
Индекс: 4–156 или 158–254 на RH, 4–254 на основном Lighter (0–3 и 157 заняты приложениями Lighter).
Выбери индекс, который ты больше нигде не используешь — старый ключ с этим индексом перестанет работать.
"""
import argparse
import asyncio
import getpass
import sys

from guardian import NETWORKS  # заодно подхватывает PROXY из .env


async def main() -> None:
    ap = argparse.ArgumentParser(description="Создать API-ключ Lighter для стража")
    ap.add_argument("--network", default="robinhood", choices=list(NETWORKS))
    ap.add_argument("--index", type=int, default=4, help="индекс API-ключа (по умолчанию 4)")
    ap.add_argument("--account", type=int, default=None, help="account index, если у адреса несколько аккаунтов")
    args = ap.parse_args()

    if args.index in (0, 1, 2, 3, 157, 255) or not 0 <= args.index <= 254:
        sys.exit("Этот индекс занят приложениями Lighter. Возьми 4–156 или 158–254.")

    import eth_account
    import lighter

    api_url, _, chain_id, label = NETWORKS[args.network]
    print(f"\nСеть: {label} ({api_url}), индекс ключа: {args.index}")
    print("Вставь приватный ключ кошелька (ввод скрыт, никуда не сохраняется):")
    eth_key = getpass.getpass("> ").strip()
    if eth_key.startswith("0x"):
        eth_key = eth_key[2:]
    address = eth_account.Account.from_key(eth_key).address
    print(f"Адрес кошелька: {address}")

    api = lighter.ApiClient(configuration=lighter.Configuration(host=api_url))
    try:
        if args.account is None:
            resp = await lighter.AccountApi(api).accounts_by_l1_address(l1_address=address)
            subs = sorted(resp.sub_accounts, key=lambda s: int(s.index))
            if not subs:
                sys.exit("На этой сети нет аккаунта для этого адреса — сначала сделай депозит на Lighter.")
            account_index = int(subs[0].index)
            if len(subs) > 1:
                print("Найдено несколько аккаунтов:", ", ".join(str(s.index) for s in subs),
                      f"— беру основной {account_index} (другой — флаг --account)")
        else:
            account_index = args.account

        priv, pub, err = lighter.create_api_key()
        if err:
            sys.exit(f"Не удалось сгенерировать ключ: {err}")
        client = lighter.SignerClient(url=api_url, account_index=account_index,
                                      api_private_keys={args.index: priv}, chain_id=chain_id)
        # nonce берём через Python-клиент SDK (он учитывает PROXY), а не внутри модуля подписи
        nonce = (await lighter.TransactionApi(api).next_nonce(account_index=account_index,
                                                              api_key_index=args.index)).nonce
        _, err = await client.change_api_key(eth_private_key=eth_key, new_pubkey=pub,
                                             nonce=nonce, api_key_index=args.index)
        if err:
            sys.exit(f"Регистрация ключа не прошла: {err}")
        print("Ключ отправлен, жду подтверждения…")
        token, terr = client.create_auth_token_with_expiry(600, api_key_index=args.index)
        orders_api = lighter.OrderApi(api)
        for _ in range(12):
            await asyncio.sleep(5)
            try:
                await orders_api.account_active_orders(authorization=token, account_index=account_index)
                break
            except Exception:  # noqa: BLE001
                continue
        else:
            sys.exit("Ключ не подтвердился за минуту. Попробуй ещё раз позже.")
        await client.close()
    finally:
        await api.close()
        eth_key = None  # noqa: F841

    p = "RH" if args.network.startswith("robinhood") else "CORE"
    print("\n✅ Готово! Впиши в .env (или в секреты GitHub / сервера):\n")
    if args.network.endswith("testnet"):
        print(f"{p}_NETWORK={args.network}")
    print(f"{p}_ACCOUNT_INDEX={account_index}")
    print(f"{p}_API_KEY_INDEX={args.index}")
    print(f"{p}_API_PRIVATE_KEY={priv}")
    print("\nЭтот API-ключ может торговать, но вывести деньги им можно только обратно на твой же кошелёк.")
    print("Не публикуй его. Отозвать — запусти этот скрипт снова с тем же --index (старый ключ перестанет работать).")


if __name__ == "__main__":
    asyncio.run(main())
