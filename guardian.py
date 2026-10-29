#!/usr/bin/env python3
"""
Lighter Guardian — страж позиций на Lighter (Robinhood Chain и основной Lighter).

Следит за твоим аккаунтом и подстраховывает стоп-лоссы:

  1. Позиция закрылась (по стопу, тейку или вручную) → отменяет оставшиеся TP/SL по этой паре,
     чтобы старые ордера не сработали потом на новой позиции.
  2. Стоп сработал, но биржа его отменила (слишком большое проскальзывание / нет ликвидности)
     → сразу закрывает позицию рыночной reduce-only заявкой.
  3. Цена в стакане ушла за стоп, а стоп так и не исполнился (mark price не дошёл до триггера
     или стоп-лимит повис) → через N секунд закрывает позицию сам.
  4. Позиция без стопа → предупреждает в Telegram.

Работает с ТВОИМ API-ключом. Ключ хранится только у тебя (в .env / секретах), никуда не отправляется.
По умолчанию включён режим DRY_RUN — страж только пишет, что СДЕЛАЛ БЫ, и ничего не отправляет на биржу.
"""
from __future__ import annotations

import asyncio
import html
import json
import logging
import math
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("guardian")
HERE = Path(__file__).resolve().parent


# ───────────────────────────── конфиг ─────────────────────────────

def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = re.split(r"\s+#", v, maxsplit=1)[0]
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_dotenv(HERE / ".env")

# Прокси для всего трафика стража (Lighter REST/WebSocket, подпись SDK, Telegram).
# Формат: http://user:pass@host:port  (поддерживаются HTTP/HTTPS-прокси)
PROXY = os.getenv("PROXY", "").strip()
if PROXY:
    for _k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        os.environ[_k] = PROXY      # SDK Lighter и его модуль подписи берут прокси из окружения


def env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    return float(v.replace(",", ".")) if v not in (None, "") else default


def env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    return default if v in (None, "") else v.strip().lower() in ("1", "true", "yes", "on", "да")


def env_mode(name: str, default: str) -> str:
    v = env(name, default).lower()
    return v if v in ("act", "alert", "off") else default


NETWORKS = {
    # имя: (REST, WebSocket, chain id, подпись в сообщениях)
    "robinhood": ("https://api.rh.lighter.xyz", "wss://api.rh.lighter.xyz/stream", 466324, "RH"),
    "robinhood_testnet": ("https://api.rh-testnet.lighter.xyz", "wss://api.rh-testnet.lighter.xyz/stream", 300, "RH-TEST"),
    "mainnet": ("https://mainnet.zklighter.elliot.ai", "wss://mainnet.zklighter.elliot.ai/stream", 304, "CORE"),
    "testnet": ("https://testnet.zklighter.elliot.ai", "wss://testnet.zklighter.elliot.ai/stream", 300, "CORE-TEST"),
}


@dataclass
class Config:
    dry_run: bool = env_bool("DRY_RUN", True)
    cleanup: str = env_mode("CLEANUP", "act")            # 1. висящие TP/SL после закрытия позиции
    failed_stop: str = env_mode("FAILED_STOP", "act")    # 2. стоп отменён биржей
    soft_stop: str = env_mode("SOFT_STOP", "act")        # 3. цена за стопом, а стоп не исполнился
    naked_alert: bool = env_bool("NAKED_ALERT", True)    # 4. позиция без стопа
    hedge: str = env_mode("HEDGE", "act")                # 5. вилка RH ↔ CORE: закрыть/подрезать вторую ногу
    hedge_debounce: float = env_float("HEDGE_DEBOUNCE_SEC", 0.7)
    soft_stop_seconds: float = env_float("SOFT_STOP_SECONDS", 5)
    soft_stop_buffer_pct: float = env_float("SOFT_STOP_BUFFER_PCT", 0.05)
    emergency_slippage_pct: float = env_float("EMERGENCY_SLIPPAGE_PCT", 1.0)
    emergency_tries: int = int(env_float("EMERGENCY_TRIES", 3))
    naked_alert_min: float = env_float("NAKED_ALERT_MIN", 2)
    cleanup_delay: float = env_float("CLEANUP_DELAY_SEC", 1.5)


SL_TYPES = {"stop-loss", "stop-loss-limit"}
TP_TYPES = {"take-profit", "take-profit-limit"}
TRIGGER_TYPES = SL_TYPES | TP_TYPES
ACTIVE = {"open", "pending", "in-progress"}
# отмены, которые означают «стоп сработал, но позицию не закрыл»
FAILED = {"canceled-too-much-slippage", "canceled-not-enough-liquidity"}


# ───────────────────────────── модели ─────────────────────────────

@dataclass
class Order:
    index: int
    market: int
    type: str
    status: str
    is_ask: bool
    reduce_only: bool
    price: float
    trigger_price: float
    remaining: float
    trigger_status: str = ""

    @classmethod
    def parse(cls, d: dict, market: int | None = None) -> "Order":
        def f(k):
            try:
                return float(d.get(k) or 0)
            except (TypeError, ValueError):
                return 0.0
        return cls(index=int(d.get("order_index") or d.get("order_id") or 0),
                   market=int(d.get("market_index", market if market is not None else -1)),
                   type=str(d.get("type", "")), status=str(d.get("status", "")),
                   is_ask=bool(d.get("is_ask")), reduce_only=bool(d.get("reduce_only")),
                   price=f("price"), trigger_price=f("trigger_price"),
                   remaining=f("remaining_base_amount"), trigger_status=str(d.get("trigger_status", "")))

    @property
    def active(self) -> bool:
        return self.status in ACTIVE

    @property
    def waiting_parent(self) -> bool:
        return self.trigger_status == "parent-order"

    def closes(self, pos: float) -> bool:
        """Ордер закрывает позицию этого знака: продажа для лонга, покупка для шорта."""
        return pos != 0 and self.is_ask == (pos > 0)

    @property
    def kind(self) -> str:
        if self.type in SL_TYPES:
            return "SL"
        if self.type in TP_TYPES:
            return "TP"
        return "reduce-only" if self.reduce_only else self.type


@dataclass
class Market:
    id: int
    symbol: str
    size_decimals: int
    price_decimals: int


@dataclass
class Quote:
    bid: float = 0.0
    ask: float = 0.0
    mark: float = 0.0
    ts: float = 0.0


def fmt(x: float, nd: int = 4) -> str:
    return f"{x:.{nd}f}".rstrip("0").rstrip(".") if x else "0"


# ───────────────────────────── логика стража ─────────────────────────────

class Guardian:
    """Вся логика решений. Биржа и Telegram передаются снаружи — так её легко тестировать."""

    def __init__(self, ex, cfg: Config, notify):
        self.ex = ex                      # объект биржи: cancel_order(), market_close(), refresh_positions()
        self.cfg = cfg
        self.notify = notify              # async notify(text)
        self.positions: dict[int, float] = {}       # market -> размер со знаком (+лонг / −шорт)
        self.tied: dict[int, int] = {}              # market -> число position-tied ордеров
        self.orders: dict[int, Order] = {}          # активные ордера по order_index
        self.quotes: dict[int, Quote] = {}
        self.pending_cleanup: dict[int, tuple[float, float]] = {}   # market -> (когда, старая позиция)
        self.soft_since: dict[int, float] = {}       # market -> с какого момента цена за стопом
        self.naked_since: dict[int, float] = {}
        self.naked_alerted: set[int] = set()
        self.closing: set[int] = set()
        self.paused = False
        self.positions_ready = False
        self.hedged: set[int] = set()               # рынки, где позиция — нога вилки
        self.pos_ts: dict[int, float] = {}          # когда позиция в последний раз пришла по WebSocket
        self._bg: set[asyncio.Task] = set()

    def spawn(self, actions: list[tuple]) -> None:
        """Выполнить действия в фоне, не блокируя поток данных от биржи."""
        if not actions:
            return
        t = asyncio.ensure_future(self.run_actions(actions))
        self._bg.add(t)
        t.add_done_callback(self._bg.discard)

    # ---------- вспомогательное ----------
    def sym(self, mid: int) -> str:
        m = self.ex.markets.get(mid)
        return f"{m.symbol if m else mid} · {self.ex.label}"

    def mode(self, scenario: str) -> str:
        m = getattr(self.cfg, scenario)
        if m == "act" and self.paused:
            return "alert"
        return m

    def market_orders(self, mid: int) -> list[Order]:
        return [o for o in self.orders.values() if o.market == mid and o.active]

    def stops_for(self, mid: int, pos: float) -> list[Order]:
        return [o for o in self.market_orders(mid)
                if o.type in SL_TYPES and o.closes(pos) and o.trigger_price > 0 and not o.waiting_parent]

    # ---------- события от биржи ----------
    def on_positions(self, data: dict[int, float], tied: dict[int, int] | None = None, snapshot: bool = False,
                     now: float | None = None, source: str = "ws") -> None:
        now = time.time() if now is None else now
        if snapshot:
            # всё, чего нет в снимке, считается закрытым
            for mid in list(self.positions):
                data.setdefault(mid, 0.0)
        for mid, new in data.items():
            if source == "rest" and now - self.pos_ts.get(mid, 0) < 15:
                continue          # по WebSocket данные свежее — REST может отставать
            if source == "ws":
                self.pos_ts[mid] = now
            old = self.positions.get(mid, 0.0)
            self.positions[mid] = new
            if tied is not None and mid in tied:
                self.tied[mid] = tied[mid]
            if not self.positions_ready:
                continue
            if old != 0 and new == 0:
                self.pending_cleanup[mid] = (now + self.cfg.cleanup_delay, old)
                self.soft_since.pop(mid, None)
            if new == 0 or (old != 0 and (old > 0) != (new > 0)):
                self.naked_since.pop(mid, None)
                self.naked_alerted.discard(mid)
            if new != 0:
                self.pending_cleanup.pop(mid, None)
        self.positions_ready = True

    def on_orders(self, orders: list[Order], snapshot: bool = False) -> list[tuple]:
        """Возвращает список действий [("emergency", mid, причина)] для отменённых биржей стопов."""
        if snapshot:
            self.orders = {o.index: o for o in orders if o.active}
            return []
        actions = []
        for o in orders:
            if o.active:
                self.orders[o.index] = o
                continue
            self.orders.pop(o.index, None)
            if o.status in FAILED:
                pos = self.positions.get(o.market, 0.0)
                reason = ("биржа отменила " + o.kind + (" (слишком большое проскальзывание)"
                          if o.status == "canceled-too-much-slippage" else " (нет ликвидности в стакане)"))
                if o.type in SL_TYPES and o.closes(pos):
                    actions.append(("emergency", o.market, f"Стоп сработал, но {reason}", "failed_stop"))
                else:
                    actions.append(("alert", o.market, f"⚠️ {self.sym(o.market)}: {reason}. "
                                                         f"Триггер {fmt(o.trigger_price)}.", "failed_stop"))
        return actions

    def on_quote(self, mid: int, bid: float, ask: float, mark: float, now: float | None = None) -> None:
        self.quotes[mid] = Quote(bid, ask, mark, time.time() if now is None else now)

    # ---------- периодическая проверка ----------
    def tick(self, now: float | None = None) -> list[tuple]:
        now = time.time() if now is None else now
        actions: list[tuple] = []

        # 1. висящие ордера после закрытия позиции
        for mid, (due, old) in list(self.pending_cleanup.items()):
            if now < due:
                continue
            del self.pending_cleanup[mid]
            if self.positions.get(mid, 0.0) != 0:
                continue
            orphans = [o for o in self.market_orders(mid)
                       if not o.waiting_parent and (o.reduce_only or (o.type in TRIGGER_TYPES and o.closes(old)))]
            if orphans:
                actions.append(("cleanup", mid, orphans, "cleanup"))

        # 3. цена за стопом, а стоп не исполнился;  4. позиция без стопа
        for mid, pos in self.positions.items():
            if pos == 0 or mid in self.closing:
                continue
            stops = self.stops_for(mid, pos)
            if not stops:
                self.soft_since.pop(mid, None)
                if self.cfg.naked_alert and self.tied.get(mid, 0) == 0 and mid not in self.hedged:
                    since = self.naked_since.setdefault(mid, now)
                    if now - since >= self.cfg.naked_alert_min * 60 and mid not in self.naked_alerted:
                        self.naked_alerted.add(mid)
                        side = "лонг" if pos > 0 else "шорт"
                        actions.append(("alert", mid, f"🛡 {self.sym(mid)}: {side} {fmt(abs(pos))} без стоп-лосса "
                                                      f"уже {self.cfg.naked_alert_min:g} мин.", "naked"))
                continue
            self.naked_since.pop(mid, None)
            q = self.quotes.get(mid)
            if not q or now - q.ts > 30 or not (q.bid and q.ask):
                continue
            buf = self.cfg.soft_stop_buffer_pct / 100
            if pos > 0:   # лонг: стоп ниже цены; смотрим, по чему можно продать (bid)
                trig = max(s.trigger_price for s in stops)
                breached, px = q.bid <= trig * (1 - buf), q.bid
            else:         # шорт: стоп выше цены; смотрим, по чему можно купить (ask)
                trig = min(s.trigger_price for s in stops)
                breached, px = q.ask >= trig * (1 + buf), q.ask
            if not breached:
                self.soft_since.pop(mid, None)
                continue
            since = self.soft_since.setdefault(mid, now)
            if now - since >= self.cfg.soft_stop_seconds:
                self.soft_since.pop(mid, None)
                where = "ниже" if pos > 0 else "выше"
                actions.append(("emergency", mid,
                                f"Стоп не сработал: цена в стакане {fmt(px)} {where} триггера {fmt(trig)} "
                                f"уже {now - since:.0f} с (mark {fmt(q.mark)})", "soft_stop"))
        return actions

    # ---------- исполнение действий ----------
    async def run_actions(self, actions: list[tuple]) -> None:
        for act in actions:
            kind, mid, payload, scenario = act
            mode = self.mode(scenario) if scenario != "naked" else "alert"
            if mode == "off":
                continue
            try:
                if kind == "alert":
                    await self.notify(payload)
                elif kind == "cleanup":
                    await self.do_cleanup(mid, payload, mode)
                elif kind == "emergency":
                    await self.emergency_close(mid, payload, mode)
            except Exception as e:  # noqa: BLE001
                log.exception("Ошибка при выполнении %s", kind)
                await self.notify(f"❗ {self.sym(mid)}: ошибка при попытке действия ({kind}): {html.escape(str(e))}")

    def _prefix(self, mode: str) -> str:
        if mode == "alert":
            return "👀 <b>[только алерт]</b> "
        if self.cfg.dry_run:
            return "🧪 <b>[DRY_RUN — ничего не отправлено]</b> "
        return ""

    async def do_cleanup(self, mid: int, orphans: list[Order], mode: str) -> None:
        desc = ", ".join(f"{o.kind} {fmt(o.trigger_price or o.price)}" for o in orphans)
        if mode == "act" and not self.cfg.dry_run:
            done, errs = [], []
            for o in orphans:
                ok, err = await self.ex.cancel_order(mid, o.index)
                (done if ok else errs).append(f"{o.kind} {fmt(o.trigger_price or o.price)}" + ("" if ok else f" ({err})"))
                if ok:
                    self.orders.pop(o.index, None)
            text = f"🧹 <b>{self.sym(mid)}</b>: позиция закрыта, отменил висящие ордера: {', '.join(done) or '—'}"
            if errs:
                text += f"\n❗ Не удалось отменить: {html.escape(', '.join(errs))} — проверь вручную"
        else:
            text = (f"{self._prefix(mode)}🧹 <b>{self.sym(mid)}</b>: позиция закрыта, "
                    f"остались ордера: {desc}. {'Отменил бы их.' if mode == 'act' else 'Отмени их вручную.'}")
        await self.notify(text)

    async def emergency_close(self, mid: int, reason: str, mode: str) -> None:
        pos = self.positions.get(mid, 0.0)
        if pos == 0 or mid in self.closing:
            return
        side = "лонг" if pos > 0 else "шорт"
        head = f"🚨 <b>{self.sym(mid)}</b>: {html.escape(reason)}.\nПозиция: {side} {fmt(abs(pos))}"
        if mode != "act" or self.cfg.dry_run:
            what = "Закрыл бы её рыночной заявкой." if mode == "act" else "Закрой позицию вручную!"
            await self.notify(f"{self._prefix(mode)}{head}\n{what}")
            return
        self.closing.add(mid)
        try:
            await self.notify(f"{head}\nЗакрываю рыночной заявкой…")
            for attempt in range(1, self.cfg.emergency_tries + 1):
                pos = self.positions.get(mid, 0.0)
                if pos == 0:
                    break
                slip = self.cfg.emergency_slippage_pct * attempt / 100
                q = self.quotes.get(mid)
                ref = (q.bid if pos > 0 else q.ask) if q else 0
                if not ref:
                    ref = await self.ex.best_price(mid, is_ask=pos > 0)
                worst = ref * (1 - slip) if pos > 0 else ref * (1 + slip)
                ok, err = await self.ex.market_close(mid, abs(pos), is_ask=pos > 0, worst_price=worst)
                if not ok:
                    log.warning("Закрытие %s, попытка %d: %s", mid, attempt, err)
                # ждём, пока позиция обнулится
                for _ in range(16):
                    await asyncio.sleep(0.25)
                    if self.positions.get(mid, 0.0) == 0:
                        break
                if self.positions.get(mid, 0.0) != 0:
                    await self.ex.refresh_positions()
                if self.positions.get(mid, 0.0) == 0:
                    await self.notify(f"✅ <b>{self.sym(mid)}</b>: позиция закрыта (попытка {attempt}, "
                                      f"допуск {slip * 100:g}%).")
                    return
            left = self.positions.get(mid, 0.0)
            if left != 0:
                await self.notify(f"❗❗ <b>{self.sym(mid)}</b>: НЕ удалось закрыть позицию за "
                                  f"{self.cfg.emergency_tries} попыток, осталось {fmt(abs(left))}. "
                                  "Закрой вручную!")
        finally:
            self.closing.discard(mid)

    def status_text(self) -> str:
        cfg = self.cfg
        mode = ("🧪 DRY_RUN (ничего не отправляю)" if cfg.dry_run else "🟢 боевой режим") + \
               (" · ⏸ пауза: только алерты" if self.paused else "")
        lines = [f"🛡 <b>Guardian · {self.ex.label}</b> — {mode}"]
        open_pos = {m: p for m, p in self.positions.items() if p != 0}
        if not open_pos:
            lines.append("Открытых позиций нет.")
        for mid, pos in sorted(open_pos.items()):
            stops = self.stops_for(mid, pos)
            tps = [o for o in self.market_orders(mid) if o.type in TP_TYPES and o.closes(pos)]
            q = self.quotes.get(mid)
            px = f" · bid {fmt(q.bid)} / ask {fmt(q.ask)} / mark {fmt(q.mark)}" if q else ""
            sl = ", ".join(fmt(s.trigger_price) for s in stops) or ("tied" if self.tied.get(mid) else "❗ нет")
            tp = ", ".join(fmt(t.trigger_price) for t in tps) or "—"
            lines.append(f"<b>{html.escape(self.sym(mid))}</b>: {'лонг' if pos > 0 else 'шорт'} {fmt(abs(pos))}"
                         f"{px}\n   SL: {sl} · TP: {tp}")
        lines.append(f"\nСценарии: висящие ордера — {cfg.cleanup}, отменённый стоп — {cfg.failed_stop}, "
                     f"стоп не сработал — {cfg.soft_stop} ({cfg.soft_stop_seconds:g} с), "
                     f"без стопа — {'on' if cfg.naked_alert else 'off'}, вилка RH↔CORE — {cfg.hedge}")
        return "\n".join(lines)


# ───────────────────────────── биржа Lighter ─────────────────────────────

class LighterExchange:
    """REST + WebSocket Lighter и подпись транзакций через официальный lighter-sdk."""

    def __init__(self, http, network: str, account_index: int | None, api_key_index: int, api_private_key: str,
                 l1_address: str = ""):
        self.http = http
        self.network = network
        self.api_url, self.ws_url, self.chain_id, self.label = NETWORKS[network]
        self.account_index = account_index
        self.l1_address = l1_address
        self.api_key_index = api_key_index
        self.api_private_key = api_private_key
        self.markets: dict[int, Market] = {}
        self.signer = None
        self.guardian: Guardian | None = None
        self._coi = int(time.time() * 1000) % (1 << 40)

    async def get(self, path: str, **params):
        import aiohttp
        async with self.http.get(f"{self.api_url}/api/v1/{path}", params=params,
                                 timeout=aiohttp.ClientTimeout(total=20)) as r:
            data = await r.json(content_type=None)
            if r.status >= 400:
                raise RuntimeError(f"{path}: HTTP {r.status} {data}")
            return data

    async def start(self) -> None:
        import lighter  # официальный SDK: pip install -r requirements.txt
        if self.account_index is None:
            data = await self.get("accountsByL1Address", l1_address=self.l1_address)
            subs = data.get("sub_accounts") or []
            if not subs:
                raise RuntimeError(f"Аккаунт для адреса {self.l1_address} не найден на {self.label}")
            self.account_index = int(min(subs, key=lambda s: int(s["index"]))["index"])
        await self.load_markets()
        self.signer = lighter.SignerClient(url=self.api_url, account_index=self.account_index,
                                           api_private_keys={self.api_key_index: self.api_private_key},
                                           chain_id=self.chain_id)
        await self.verify_key()
        log.info("%s: аккаунт %s, ключ %s — ок, рынков %d", self.label, self.account_index,
                 self.api_key_index, len(self.markets))

    async def verify_key(self) -> None:
        """Проверка ключа запросом с подписанным токеном (через наш HTTP-клиент — работает и через прокси)."""
        import aiohttp
        token = self.auth_token(600)
        async with self.http.get(f"{self.api_url}/api/v1/accountActiveOrders",
                                 params={"account_index": self.account_index},
                                 headers={"authorization": token},
                                 timeout=aiohttp.ClientTimeout(total=20)) as r:
            data = await r.json(content_type=None)
        if r.status >= 400 or (isinstance(data, dict) and int(data.get("code", 200)) != 200):
            raise RuntimeError(f"API-ключ {self.api_key_index} не подходит к аккаунту {self.account_index} "
                               f"на {self.label}: {data}")

    async def load_markets(self) -> None:
        data = await self.get("orderBookDetails", filter="perp")
        for m in data.get("order_book_details") or []:
            self.markets[int(m["market_id"])] = Market(int(m["market_id"]), m["symbol"],
                                                       int(m["size_decimals"]), int(m["price_decimals"]))

    def auth_token(self, seconds: int = 3600) -> str:
        token, err = self.signer.create_auth_token_with_expiry(seconds, api_key_index=self.api_key_index)
        if err:
            raise RuntimeError(f"auth token: {err}")
        return token

    def _next_coi(self) -> int:
        self._coi = (self._coi + 1) % (1 << 40)
        return self._coi

    async def cancel_order(self, mid: int, order_index: int) -> tuple[bool, str]:
        _, resp, err = await self.signer.cancel_order(market_index=mid, order_index=order_index)
        if err or resp is None or getattr(resp, "code", 200) != 200:
            return False, str(err or getattr(resp, "message", "") or "ошибка")
        return True, ""

    async def best_price(self, mid: int, is_ask: bool) -> float:
        data = await self.get("orderBookOrders", market_id=mid, limit=1)
        side = data.get("bids" if is_ask else "asks") or []
        return float(side[0]["price"]) if side else 0.0

    async def market_close(self, mid: int, size: float, is_ask: bool, worst_price: float) -> tuple[bool, str]:
        m = self.markets[mid]
        base = int(round(size * 10 ** m.size_decimals))
        # округляем цену в «безопасную» сторону, чтобы не сузить допуск
        scale = 10 ** m.price_decimals
        price = math.floor(worst_price * scale) if is_ask else math.ceil(worst_price * scale)
        price = max(price, 1)
        _, resp, err = await self.signer.create_market_order(
            market_index=mid, client_order_index=self._next_coi(), base_amount=base,
            avg_execution_price=price, is_ask=is_ask, reduce_only=True)
        if err or resp is None or getattr(resp, "code", 200) != 200:
            return False, str(err or getattr(resp, "message", "") or "ошибка")
        return True, ""

    async def refresh_positions(self) -> None:
        data = await self.get("account", by="index", value=str(self.account_index))
        accs = data.get("accounts") or []
        if not accs or not self.guardian:
            return
        pos, tied = parse_positions(accs[0].get("positions") or [])
        self.guardian.on_positions(pos, tied, snapshot=True, source="rest")

    async def stream(self) -> None:
        """WebSocket: ордера, позиции, цены. Переподключение раз в 50 минут — чтобы обновить токен."""
        import aiohttp
        g = self.guardian
        backoff = 1
        while True:
            try:
                token = self.auth_token(3600)
                async with self.http.ws_connect(self.ws_url, heartbeat=None, max_msg_size=0,
                                                proxy=PROXY or None) as ws:
                    acc = self.account_index
                    for ch in (f"account_all_positions/{acc}", f"account_all_orders/{acc}"):
                        await ws.send_json({"type": "subscribe", "channel": ch, "auth": token})
                    await ws.send_json({"type": "subscribe", "channel": "market_stats/all"})
                    log.info("%s: WebSocket подключён", self.label)
                    backoff = 1
                    deadline = time.time() + 50 * 60
                    last_ping = time.time()
                    while time.time() < deadline:
                        try:
                            msg = await ws.receive(timeout=20)
                        except asyncio.TimeoutError:
                            msg = None
                        if time.time() - last_ping > 50:
                            await ws.send_json({"type": "ping"})
                            last_ping = time.time()
                        if msg is None:
                            continue
                        if msg.type != aiohttp.WSMsgType.TEXT:
                            if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR,
                                            aiohttp.WSMsgType.CLOSING):
                                break
                            continue
                        await self.on_ws(json.loads(msg.data))
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                log.warning("%s: WebSocket ошибка: %s", self.label, e)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)

    async def on_ws(self, msg: dict) -> None:
        g = self.guardian
        t = str(msg.get("type", ""))
        snap = t.startswith("subscribed/")
        if t.endswith("account_all_positions"):
            pos, tied = parse_positions(msg.get("positions") or {})
            g.on_positions(pos, tied, snapshot=snap)
        elif t.endswith("account_all_orders"):
            orders = []
            for mkt, lst in (msg.get("orders") or {}).items():
                for d in lst or []:
                    orders.append(Order.parse(d, int(mkt)))
            g.spawn(g.on_orders(orders, snapshot=snap))
        elif t.endswith("market_stats"):
            ms = msg.get("market_stats") or {}
            items = [ms] if "market_id" in ms else list(ms.values())
            for s in items:
                try:
                    g.on_quote(int(s["market_id"]), float(s.get("best_bid_price") or 0),
                               float(s.get("best_ask_price") or 0), float(s.get("mark_price") or 0))
                except (KeyError, TypeError, ValueError):
                    pass
        elif "error" in msg:
            log.warning("%s: WebSocket: %s", self.label, msg)


def parse_positions(raw) -> tuple[dict[int, float], dict[int, int]]:
    items = raw.values() if isinstance(raw, dict) else raw
    pos, tied = {}, {}
    for p in items:
        try:
            mid = int(p["market_id"])
            size = float(p.get("position") or 0)
            sign = int(p.get("sign") or 0)
        except (KeyError, TypeError, ValueError):
            continue
        pos[mid] = size * (1 if sign >= 0 else -1) if size else 0.0
        tied[mid] = int(p.get("position_tied_order_count") or 0)
    return pos, tied


# ───────────────────────────── Telegram ─────────────────────────────

class Telegram:
    def __init__(self, http, token: str, chat_id: str):
        self.http, self.token, self.chat_id = http, token, chat_id
        self.offset = 0

    async def call(self, method: str, **params):
        if not self.token:
            return None
        import aiohttp
        async with self.http.post(f"https://api.telegram.org/bot{self.token}/{method}", json=params,
                                  timeout=aiohttp.ClientTimeout(total=params.get("timeout", 0) + 15)) as r:
            return await r.json(content_type=None)

    async def send(self, text: str) -> None:
        log.info("TG: %s", re.sub(r"<[^>]+>", "", text))
        if not (self.token and self.chat_id):
            return
        try:
            await self.call("sendMessage", chat_id=self.chat_id, text=text[:4000], parse_mode="HTML",
                            disable_web_page_preview=True)
        except Exception as e:  # noqa: BLE001
            log.warning("Telegram: %s", e)

    async def poll(self, guardians: list[Guardian], hedge=None) -> None:
        if not (self.token and self.chat_id):
            return
        await self.call("setMyCommands", commands=[
            {"command": "status", "description": "Позиции и стопы"},
            {"command": "pairs", "description": "Вилки RH ↔ CORE"},
            {"command": "pause", "description": "Только алерты, без действий"},
            {"command": "resume", "description": "Снова действовать"},
        ])
        while True:
            try:
                data = await self.call("getUpdates", offset=self.offset, timeout=30, allowed_updates=["message"])
                for upd in (data or {}).get("result", []):
                    self.offset = upd["update_id"] + 1
                    msg = upd.get("message") or {}
                    if str((msg.get("chat") or {}).get("id")) != str(self.chat_id):
                        continue      # отвечаем только владельцу
                    cmd = (msg.get("text") or "").split("@")[0].strip().lower()
                    if cmd == "/status" or cmd == "/start":
                        parts = [g.status_text() for g in guardians]
                        if hedge:
                            parts.append(hedge.pairs_text())
                        await self.send("\n\n".join(parts))
                    elif cmd == "/pairs":
                        await self.send(hedge.pairs_text() if hedge else
                                        "Вилки работают, когда подключены обе биржи: RH и CORE.")
                    elif cmd == "/pause":
                        for g in guardians:
                            g.paused = True
                        await self.send("⏸ Пауза: только алерты, никаких действий на бирже. /resume — вернуть.")
                    elif cmd == "/resume":
                        for g in guardians:
                            g.paused = False
                        await self.send("▶️ Страж снова действует.")
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                log.warning("Telegram polling: %s", e)
                await asyncio.sleep(5)


# ───────────────────────────── запуск ─────────────────────────────

def exchange_configs() -> list[dict]:
    """Блоки настроек RH_* и CORE_* — можно включить один или оба."""
    out = []
    for prefix, default_net in (("RH", "robinhood"), ("CORE", "mainnet")):
        key = env(f"{prefix}_API_PRIVATE_KEY")
        if not key:
            continue
        net = env(f"{prefix}_NETWORK", default_net)
        if net not in NETWORKS:
            raise SystemExit(f"{prefix}_NETWORK: неизвестная сеть {net}. Варианты: {', '.join(NETWORKS)}")
        acc = env(f"{prefix}_ACCOUNT_INDEX")
        l1 = env(f"{prefix}_L1_ADDRESS")
        if not acc and not l1:
            raise SystemExit(f"Укажи {prefix}_ACCOUNT_INDEX или {prefix}_L1_ADDRESS")
        out.append(dict(network=net, account_index=int(acc) if acc else None, l1_address=l1,
                        api_key_index=int(env(f"{prefix}_API_KEY_INDEX", "4")), api_private_key=key))
    if not out:
        raise SystemExit("Не задан ни один ключ: RH_API_PRIVATE_KEY и/или CORE_API_PRIVATE_KEY (см. .env.example)")
    return out


async def main_async() -> None:
    import aiohttp
    cfg = Config()
    max_runtime = env_float("MAX_RUNTIME_MIN", 0) * 60
    if PROXY:
        log.info("Весь трафик идёт через прокси %s", re.sub(r"//[^@/]*@", "//***@", PROXY))
    async with aiohttp.ClientSession(trust_env=True) as http:
        tg = Telegram(http, env("TG_TOKEN"), env("TG_CHAT_ID"))
        guardians, tasks = [], []
        for c in exchange_configs():
            ex = LighterExchange(http, **c)
            await ex.start()
            g = Guardian(ex, cfg, tg.send)
            ex.guardian = g
            await ex.refresh_positions()
            guardians.append(g)

        hedge = None
        if len(guardians) >= 2 and cfg.hedge != "off":
            from hedge import HedgeManager
            hedge = HedgeManager({g.ex.label: g for g in guardians}, cfg, tg.send)

            async def hedge_ticker():
                while True:
                    hedge.spawn(hedge.tick())
                    await asyncio.sleep(0.25)

        async def ticker(g: Guardian):
            while True:
                await g.run_actions(g.tick())
                await asyncio.sleep(0.5)

        async def reconcile(g: Guardian):
            while True:
                await asyncio.sleep(30)
                try:
                    await g.ex.refresh_positions()
                except Exception as e:  # noqa: BLE001
                    log.warning("%s: сверка позиций: %s", g.ex.label, e)

        for g in guardians:
            tasks += [g.ex.stream(), ticker(g), reconcile(g)]
        if hedge:
            tasks.append(hedge_ticker())
        tasks.append(tg.poll(guardians, hedge))
        if env_bool("STARTUP_MESSAGE", True):
            await tg.send("\n\n".join(g.status_text() for g in guardians))
        runner = asyncio.gather(*tasks)
        if max_runtime > 0:
            try:
                await asyncio.wait_for(runner, timeout=max_runtime)
            except asyncio.TimeoutError:
                log.info("Плановое завершение (MAX_RUNTIME_MIN)")
        else:
            await runner


def main() -> None:
    logging.basicConfig(level=env("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
