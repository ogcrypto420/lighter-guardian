#!/usr/bin/env python3
"""
Lighter Guardian — страж позиций на Lighter (Robinhood Chain и основной Lighter).

  1. Позиция закрылась → отменяет оставшиеся TP/SL по этой паре.
  2. Стоп сработал, но биржа его отменила (проскальзывание / нет ликвидности) → закрывает позицию.
  3. Цена в стакане за стопом, а стоп не исполнился → через N секунд закрывает позицию.
  4. Позиция без стопа → предупреждает.
  5. Вилка RH ↔ CORE: одна нога закрылась/уменьшилась → вторая закрывается/подрезается (hedge.py).

Безопасность:
  • все ключи, адреса, прокси и токен Telegram — в зашифрованном хранилище (vault.py), пароль не сохраняется;
  • транзакции подписываются локально официальным модулем Lighter (проверка SHA-256, без доступа к сети);
  • в сеть программа ходит только на адреса Lighter и Telegram (белый список);
  • секреты вымарываются из логов и сообщений; дампы памяти процесса запрещены;
  • в Telegram по умолчанию уходят уведомления без цифр (TG_DETAIL=short).
"""
from __future__ import annotations

import asyncio
import html
import json
import logging
import math
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from security import S, T, register_secret, redact, render, strip_marks  # noqa: F401  (strip_marks — для тестов)

log = logging.getLogger("guardian")
HERE = Path(__file__).resolve().parent


# ───────────────────────────── конфиг ─────────────────────────────
# .env — только поведение (сценарии, пороги). Ключи и данные кошельков — в зашифрованном хранилище.

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

SECRETS: dict[str, str] = {}      # заполняется из хранилища при запуске; в os.environ не попадает


def env(name: str, default: str = "") -> str:
    v = SECRETS.get(name)
    if v is None:
        v = os.getenv(name, default)
    return (v or "").strip()


def env_names() -> set[str]:
    return set(SECRETS) | set(os.environ)


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
    # WebSocket — только чтение (?readonly=true): без этого Lighter отвечает 400. Транзакции идут через REST.
    "robinhood": ("https://api.rh.lighter.xyz", "wss://api.rh.lighter.xyz/stream?readonly=true", 466324, "RH"),
    "robinhood_testnet": ("https://api.rh-testnet.lighter.xyz", "wss://api.rh-testnet.lighter.xyz/stream?readonly=true",
                          300, "RH-TEST"),
    "mainnet": ("https://mainnet.zklighter.elliot.ai", "wss://mainnet.zklighter.elliot.ai/stream?readonly=true", 304, "CORE"),
    "testnet": ("https://testnet.zklighter.elliot.ai", "wss://testnet.zklighter.elliot.ai/stream?readonly=true",
                300, "CORE-TEST"),
}
TELEGRAM_HOST = "api.telegram.org"
# Единственные адреса, куда страж может ходить в сеть
ALLOWED_HOSTS = {urlsplit(u).hostname for net in NETWORKS.values() for u in net[:2]} | {TELEGRAM_HOST}


@dataclass
class Config:
    dry_run: bool = env_bool("DRY_RUN", True)
    cleanup: str = env_mode("CLEANUP", "act")            # 1. висящие TP/SL после закрытия позиции
    failed_stop: str = env_mode("FAILED_STOP", "act")    # 2. стоп отменён биржей
    soft_stop: str = env_mode("SOFT_STOP", "act")        # 3. цена за стопом, а стоп не исполнился
    naked_alert: bool = env_bool("NAKED_ALERT", True)    # 4. позиция без стопа
    hedge: str = env_mode("HEDGE", "act")                # 5. вилка RH ↔ CORE: закрыть/подрезать вторую ногу
    hedge_debounce: float = env_float("HEDGE_DEBOUNCE_SEC", 3)
    soft_stop_seconds: float = env_float("SOFT_STOP_SECONDS", 5)
    soft_stop_buffer_pct: float = env_float("SOFT_STOP_BUFFER_PCT", 0.05)
    emergency_slippage_pct: float = env_float("EMERGENCY_SLIPPAGE_PCT", 1.0)
    emergency_tries: int = int(env_float("EMERGENCY_TRIES", 3))
    naked_alert_min: float = env_float("NAKED_ALERT_MIN", 2)
    cleanup_delay: float = env_float("CLEANUP_DELAY_SEC", 1.5)
    # мягкий стоп не закрывает сам, если стакан шире этого (%): только алерт — защита от «дыр» в тонком стакане
    soft_stop_max_spread_pct: float = env_float("SOFT_STOP_MAX_SPREAD_PCT", 2.0)
    retry_pause_sec: float = env_float("EMERGENCY_RETRY_PAUSE_SEC", 60)   # пауза после неудачного закрытия


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


def mask_proxy(p: str) -> str:
    """http://user:pass@host:port → host:port (пароль никуда не попадает)."""
    return re.sub(r"^\w+://", "", re.sub(r"//[^@/]*@", "//", p)) if p else ""


def fmt(x: float, nd: int = 4) -> str:
    return f"{x:.{nd}f}".rstrip("0").rstrip(".") if x else "0"


def num(x: float, nd: int = 4) -> str:
    """Число, которое скрывается в уведомлениях с TG_DETAIL=short/minimal."""
    return S(fmt(x, nd))


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
        self.orders_ts: dict[int, float] = {}       # когда ордера рынка в последний раз пришли по WebSocket
        self.soft_alerted: set[int] = set()         # о мягком стопе уже предупредили (алерт / DRY_RUN) — не повторяем
        self.retry_after: dict[int, float] = {}     # market -> раньше этого времени повторно не закрываем
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
        return f"{T(html.escape(str(m.symbol if m else mid)))} · {html.escape(self.ex.label)}"

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
                self.soft_alerted.discard(mid)
                self.retry_after.pop(mid, None)
            if new != 0:
                self.pending_cleanup.pop(mid, None)
        self.positions_ready = True

    def on_orders(self, orders: list[Order], snapshot: bool = False, now: float | None = None) -> list[tuple]:
        """Возвращает список действий [("emergency", mid, причина)] для отменённых биржей стопов."""
        now = time.time() if now is None else now
        if snapshot:
            new = {o.index: o for o in orders if o.active}
            actions = self._vanished_stops(set(self.positions), new, now)
            self.orders = new
            return actions
        actions = []
        for o in orders:
            self.orders_ts[o.market] = now
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
                                                         f"Триггер {num(o.trigger_price)}.", "failed_stop"))
        return actions

    def sync_orders(self, mid: int, orders: list[Order], now: float | None = None) -> list[tuple]:
        """Сверка ордеров одного рынка по REST: убирает «призраков» (если событие отмены потерялось)
        и ловит стоп, который исчез, хотя цена уже за ним."""
        now = time.time() if now is None else now
        if now - self.orders_ts.get(mid, 0) < 5:
            return []                     # по WebSocket только что пришло свежее — REST может отставать
        others = {i: o for i, o in self.orders.items() if o.market != mid}
        new = {**others, **{o.index: o for o in orders if o.active and o.market == mid}}
        actions = self._vanished_stops({mid}, new, now)
        self.orders = new
        return actions

    def _vanished_stops(self, mids, new_orders: dict[int, Order], now: float) -> list[tuple]:
        """Стоп пропал без события отмены (например, пока переподключались), позиция открыта,
        а mark уже за его триггером — значит, стоп сработал, но позицию не закрыл."""
        actions = []
        for mid in mids:
            pos = self.positions.get(mid, 0.0)
            q = self.quotes.get(mid)
            if pos == 0 or mid in self.closing or not q or not q.mark or now - q.ts > 30:
                continue
            gone = [o for o in self.stops_for(mid, pos) if o.index not in new_orders]
            crossed = [o for o in gone if (q.mark <= o.trigger_price if pos > 0 else q.mark >= o.trigger_price)]
            still = [o for o in new_orders.values()
                     if o.market == mid and o.type in SL_TYPES and o.closes(pos) and not o.waiting_parent]
            if crossed and not still:
                actions.append(("emergency", mid, f"Стоп {num(crossed[0].trigger_price)} пропал, а mark "
                                                  f"{num(q.mark)} уже за триггером — похоже, стоп сработал, "
                                                  "но позицию не закрыл", "failed_stop"))
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
                        actions.append(("alert", mid, f"🛡 {self.sym(mid)}: {side} {num(abs(pos))} без стоп-лосса "
                                                      f"уже {self.cfg.naked_alert_min:g} мин.", "naked"))
                continue
            self.naked_since.pop(mid, None)
            q = self.quotes.get(mid)
            if not q or now - q.ts > 30 or not (q.bid and q.ask) or q.ask <= q.bid:
                continue
            buf = self.cfg.soft_stop_buffer_pct / 100
            mid_px = (q.bid + q.ask) / 2
            # пробой — когда за стопом и цена, по которой закроемся, и середина стакана:
            # одна «дыра» на стороне bid/ask в тонком стакане пробоем не считается
            if pos > 0:   # лонг: стоп ниже цены; продаём по bid
                trig = max(s.trigger_price for s in stops)
                breached, px = q.bid <= trig * (1 - buf) and mid_px <= trig, q.bid
            else:         # шорт: стоп выше цены; покупаем по ask
                trig = min(s.trigger_price for s in stops)
                breached, px = q.ask >= trig * (1 + buf) and mid_px >= trig, q.ask
            if not breached:
                self.soft_since.pop(mid, None)
                self.soft_alerted.discard(mid)
                continue
            if mid in self.soft_alerted or now < self.retry_after.get(mid, 0):
                continue
            since = self.soft_since.setdefault(mid, now)
            if now - since >= self.cfg.soft_stop_seconds:
                self.soft_since.pop(mid, None)
                where = "ниже" if pos > 0 else "выше"
                reason = (f"Стоп не сработал: цена в стакане {num(px)} {where} триггера {num(trig)} "
                          f"уже {now - since:.0f} с (mark {num(q.mark)})")
                spread_pct = (q.ask - q.bid) / mid_px * 100
                if spread_pct > self.cfg.soft_stop_max_spread_pct:
                    self.soft_alerted.add(mid)
                    actions.append(("alert", mid, f"⚠️ <b>{self.sym(mid)}</b>: {reason}. Но стакан слишком широкий "
                                                  f"(спред {num(spread_pct, 2)}%) — сам не закрываю, проверь вручную.",
                                    "soft_stop"))
                    continue
                if self.mode("soft_stop") != "act" or self.cfg.dry_run:
                    self.soft_alerted.add(mid)       # в режиме алерта / DRY_RUN — одно сообщение на пробой
                actions.append(("emergency", mid, reason, "soft_stop"))
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
                await self.notify(f"❗ {self.sym(mid)}: ошибка при попытке действия ({kind}): "
                                  f"{S(html.escape(redact(str(e))))}")

    def _prefix(self, mode: str) -> str:
        if mode == "alert":
            return "👀 <b>[только алерт]</b> "
        if self.cfg.dry_run:
            return "🧪 <b>[DRY_RUN — ничего не отправлено]</b> "
        return ""

    async def do_cleanup(self, mid: int, orphans: list[Order], mode: str) -> None:
        desc = ", ".join(f"{o.kind} {num(o.trigger_price or o.price)}" for o in orphans)
        if mode == "act" and not self.cfg.dry_run:
            done, errs = [], []
            for o in orphans:
                ok, err = await self.ex.cancel_order(mid, o.index)
                (done if ok else errs).append(f"{o.kind} {num(o.trigger_price or o.price)}" +
                                              ("" if ok else f" ({S(html.escape(redact(str(err))))})"))
                if ok:
                    self.orders.pop(o.index, None)
            text = f"🧹 <b>{self.sym(mid)}</b>: позиция закрыта, отменил висящие ордера: {', '.join(done) or '—'}"
            if errs:
                text += f"\n❗ Не удалось отменить: {', '.join(errs)} — проверь вручную"
        else:
            text = (f"{self._prefix(mode)}🧹 <b>{self.sym(mid)}</b>: позиция закрыта, "
                    f"остались ордера: {desc}. {'Отменил бы их.' if mode == 'act' else 'Отмени их вручную.'}")
        await self.notify(text)

    async def emergency_close(self, mid: int, reason: str, mode: str) -> None:
        pos = self.positions.get(mid, 0.0)
        if pos == 0 or mid in self.closing:
            return
        side = "лонг" if pos > 0 else "шорт"
        head = f"🚨 <b>{self.sym(mid)}</b>: {reason}.\nПозиция: {side} {num(abs(pos))}"
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
                ref = await self.close_ref(mid, is_ask=pos > 0)
                if not ref:
                    raise RuntimeError("нет цены в стакане — закрывать по рынку вслепую не буду, закрой вручную")
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
                self.retry_after[mid] = time.time() + self.cfg.retry_pause_sec
                await self.notify(f"❗❗ <b>{self.sym(mid)}</b>: НЕ удалось закрыть позицию за "
                                  f"{self.cfg.emergency_tries} попыток, осталось {num(abs(left))}. "
                                  f"Закрой вручную! (Повторю не раньше чем через {self.cfg.retry_pause_sec:g} с.)")
        except Exception:
            self.retry_after[mid] = time.time() + self.cfg.retry_pause_sec
            raise
        finally:
            self.closing.discard(mid)

    async def close_ref(self, mid: int, is_ask: bool) -> float:
        """Цена, от которой считаем допуск закрытия: свежая из потока, иначе — из стакана по REST."""
        q = self.quotes.get(mid)
        if q and time.time() - q.ts < 5:
            ref = q.bid if is_ask else q.ask
            if ref:
                return ref
        try:
            ref = await self.ex.best_price(mid, is_ask=is_ask)
            if ref:
                return ref
        except Exception as e:  # noqa: BLE001
            log.warning("%s: цена из стакана: %s", self.ex.label, redact(str(e)))
        if q and time.time() - q.ts < 60:
            return (q.bid if is_ask else q.ask) or 0.0
        return 0.0

    def status_text(self) -> str:
        cfg = self.cfg
        mode = ("🧪 DRY_RUN (ничего не отправляю)" if cfg.dry_run else "🟢 боевой режим") + \
               (" · ⏸ пауза: только алерты" if self.paused else "")
        lines = [f"🛡 <b>Guardian · {html.escape(self.ex.label)}</b> — {mode}"]
        open_pos = {m: p for m, p in self.positions.items() if p != 0}
        if not open_pos:
            lines.append("Открытых позиций нет.")
        for mid, pos in sorted(open_pos.items()):
            stops = self.stops_for(mid, pos)
            tps = [o for o in self.market_orders(mid) if o.type in TP_TYPES and o.closes(pos)]
            q = self.quotes.get(mid)
            px = f" · bid {num(q.bid)} / ask {num(q.ask)} / mark {num(q.mark)}" if q else ""
            sl = ", ".join(num(s.trigger_price) for s in stops) or ("tied" if self.tied.get(mid) else "❗ нет")
            tp = ", ".join(num(t.trigger_price) for t in tps) or "—"
            lines.append(f"<b>{self.sym(mid)}</b>: {'лонг' if pos > 0 else 'шорт'} {num(abs(pos))}"
                         f"{px}\n   SL: {sl} · TP: {tp}")
        lines.append(f"\nСценарии: висящие ордера — {cfg.cleanup}, отменённый стоп — {cfg.failed_stop}, "
                     f"стоп не сработал — {cfg.soft_stop} ({cfg.soft_stop_seconds:g} с), "
                     f"без стопа — {'on' if cfg.naked_alert else 'off'}, вилка RH↔CORE — {cfg.hedge}")
        return "\n".join(lines)


# ───────────────────────────── биржа Lighter ─────────────────────────────

class LighterExchange:
    """REST + WebSocket Lighter. Транзакции подписываются локально (lighter_signer), отправляются нашим кодом."""

    def __init__(self, http, network: str, account_index: int | None, api_key_index: int, api_private_key: str,
                 l1_address: str = "", wallet: int = 1, wallet_name: str = "", proxy: str = ""):
        self.http = http
        self.proxy = proxy or None          # свой прокси кошелька (или общий PROXY)
        self.network = network
        self.api_url, self.ws_url, self.chain_id, self.venue = NETWORKS[network]
        self.wallet = wallet
        self.wallet_name = wallet_name
        self.label = f"#{wallet}{' ' + wallet_name if wallet_name else ''} {self.venue}"
        self.account_index = account_index
        self.l1_address = l1_address
        self.api_key_index = api_key_index
        self._api_private_key = api_private_key
        self.markets: dict[int, Market] = {}
        self.signer = None
        self.guardian: Guardian | None = None
        self._coi = int(time.time() * 1000) % (1 << 40)
        self._tx_lock = asyncio.Lock()      # одна транзакция за раз: nonce идут строго по порядку
        self.last_msg = time.time()         # когда последний раз что-то пришло по WebSocket
        self.sub_error = ""                 # биржа отказала в подписке на ордера/позиции
        self._token: tuple[str, float] = ("", 0.0)

    def _timeout(self, total: float = 20):
        import aiohttp
        return aiohttp.ClientTimeout(total=total)

    async def get(self, path: str, headers: dict | None = None, **params):
        async with self.http.get(f"{self.api_url}/api/v1/{path}", params=params, headers=headers,
                                 proxy=self.proxy, timeout=self._timeout()) as r:
            data = await r.json(content_type=None)
            if r.status >= 400:
                raise RuntimeError(f"{path}: HTTP {r.status} {data}")
            return data

    async def start(self) -> None:
        from lighter_signer import Signer
        if self.account_index is None:
            data = await self.get("accountsByL1Address", l1_address=self.l1_address)
            subs = data.get("sub_accounts") or []
            if not subs:
                raise RuntimeError(f"Аккаунт для кошелька не найден на {self.label}")
            self.account_index = int(min(subs, key=lambda s: int(s["index"]))["index"])
        await self.load_markets()
        if self.signer is None:
            self.signer = Signer(self.account_index, self.api_key_index, self._api_private_key, self.chain_id)
            self._api_private_key = None    # дальше ключ живёт только внутри модуля подписи
        await self.verify_key()
        log.info("%s: аккаунт %s, ключ %s — ок, рынков %d%s", self.label, self.account_index,
                 self.api_key_index, len(self.markets),
                 f", прокси {mask_proxy(self.proxy)}" if self.proxy else "")

    async def verify_key(self) -> None:
        """Проверка ключа: закрытый запрос с подписанным токеном. Ошибка — если ключ не тот."""
        token = self.auth_token(600)
        params = {"account_index": self.account_index}
        if self.markets:
            params["market_id"] = min(self.markets)
        async with self.http.get(f"{self.api_url}/api/v1/accountActiveOrders", params=params,
                                 headers={"authorization": token}, proxy=self.proxy,
                                 timeout=self._timeout()) as r:
            data = await r.json(content_type=None)
        if r.status >= 400 or (isinstance(data, dict) and int(data.get("code", 200)) != 200):
            msg = data.get("message") if isinstance(data, dict) else data
            raise RuntimeError(f"API-ключ {self.api_key_index} не подходит к аккаунту {self.account_index} "
                               f"на {self.label}: {redact(str(msg))}")

    async def load_markets(self) -> None:
        data = await self.get("orderBookDetails", filter="perp")
        for m in data.get("order_book_details") or []:
            self.markets[int(m["market_id"])] = Market(int(m["market_id"]), m["symbol"],
                                                       int(m["size_decimals"]), int(m["price_decimals"]))

    def auth_token(self, seconds: int = 3600) -> str:
        token = self.signer.auth_token(int(time.time()) + seconds)
        register_secret(token)
        return token

    def rest_token(self) -> str:
        """Токен для закрытых REST-запросов: живёт 10 минут, обновляем раз в 5."""
        tok, made = self._token
        if not tok or time.time() - made > 300:
            self._token = (self.auth_token(600), time.time())
        return self._token[0]

    async def fetch_active_orders(self, mid: int) -> list[Order] | None:
        """Активные ордера одного рынка по REST (для сверки). None — если биржа не ответила как надо."""
        async with self.http.get(f"{self.api_url}/api/v1/accountActiveOrders",
                                 params={"account_index": self.account_index, "market_id": mid},
                                 headers={"authorization": self.rest_token()}, proxy=self.proxy,
                                 timeout=self._timeout()) as r:
            data = await r.json(content_type=None)
        if r.status >= 400 or not isinstance(data, dict) or int(data.get("code", 200)) != 200 \
                or not isinstance(data.get("orders"), list):
            return None
        return [Order.parse(d, mid) for d in data["orders"]]

    def _next_coi(self) -> int:
        self._coi = (self._coi + 1) % (1 << 40)
        return self._coi

    async def _nonce(self) -> int:
        data = await self.get("nextNonce", account_index=self.account_index, api_key_index=self.api_key_index)
        return int(data["nonce"])

    async def _send(self, build) -> tuple[bool, str]:
        """build(nonce) → (tx_type, tx_info). Подпись локально, отправка POST /api/v1/sendTx.
        Если биржа отвергла nonce — один повтор со свежим nonce."""
        async with self._tx_lock:
            for attempt in range(2):
                tx_type, tx_info = build(await self._nonce())
                async with self.http.post(f"{self.api_url}/api/v1/sendTx",
                                          data={"tx_type": str(tx_type), "tx_info": tx_info},
                                          headers={"Accept": "application/json"},
                                          proxy=self.proxy, timeout=self._timeout()) as r:
                    data = await r.json(content_type=None)
                code = int(data.get("code", r.status)) if isinstance(data, dict) else r.status
                if r.status < 400 and code == 200:
                    return True, ""
                msg = str(data.get("message") if isinstance(data, dict) else data)
                if attempt == 0 and "nonce" in msg.lower():
                    continue
                return False, redact(msg or f"HTTP {r.status}")
        return False, "nonce"

    async def cancel_order(self, mid: int, order_index: int) -> tuple[bool, str]:
        return await self._send(lambda n: self.signer.cancel_order(mid, order_index, n))

    async def best_price(self, mid: int, is_ask: bool) -> float:
        data = await self.get("orderBookOrders", market_id=mid, limit=1)
        side = data.get("bids" if is_ask else "asks") or []
        return float(side[0]["price"]) if side else 0.0

    async def market_close(self, mid: int, size: float, is_ask: bool, worst_price: float) -> tuple[bool, str]:
        if mid not in self.markets:          # рынок появился после запуска
            await self.load_markets()
        m = self.markets[mid]
        if worst_price <= 0:
            return False, "нет цены"
        base = int(round(size * 10 ** m.size_decimals))
        # округляем цену в «безопасную» сторону, чтобы не сузить допуск
        scale = 10 ** m.price_decimals
        price = max(math.floor(worst_price * scale) if is_ask else math.ceil(worst_price * scale), 1)
        coi = self._next_coi()
        return await self._send(lambda n: self.signer.market_order(mid, coi, base, price, is_ask, True, n))

    async def _fetch_positions(self) -> tuple[dict, dict] | None:
        data = await self.get("account", by="index", value=str(self.account_index))
        accs = data.get("accounts") or []
        if not accs or not isinstance(accs[0].get("positions"), list):
            return None
        return parse_positions(accs[0]["positions"])

    async def refresh_positions(self) -> None:
        g = self.guardian
        got = await self._fetch_positions() if g else None
        if got is None:
            return
        pos, tied = got
        # REST говорит «позиция закрыта» — перепроверяем ещё раз: случайный сбой API не должен
        # выглядеть как закрытие (иначе отменили бы стопы и закрыли вторую ногу вилки)
        gone = [m for m, p in g.positions.items() if p != 0 and pos.get(m, 0.0) == 0]
        if gone:
            await asyncio.sleep(1.5)
            again = await self._fetch_positions()
            if again is None:
                return
            for m in gone:
                if again[0].get(m, 0.0) != 0:
                    pos[m] = again[0][m]
        g.on_positions(pos, tied, snapshot=True, source="rest")

    async def stream(self) -> None:
        """WebSocket: ордера, позиции, цены. Переподключение раз в 50 минут — чтобы обновить токен."""
        import aiohttp
        backoff = 1
        while True:
            try:
                token = self.auth_token(3600)
                async with self.http.ws_connect(self.ws_url, heartbeat=None, max_msg_size=0,
                                                proxy=self.proxy) as ws:
                    self.last_msg = time.time()
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
                            if time.time() - self.last_msg > 90:     # соединение «висит» молча
                                log.warning("%s: WebSocket молчит 90 с — переподключаюсь", self.label)
                                break
                            continue
                        self.last_msg = time.time()
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
            if snap:
                self.sub_error = ""
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
            err = msg.get("error")
            text = redact(str(err.get("message") if isinstance(err, dict) else err))
            log.warning("%s: WebSocket: %s", self.label, text)
            if "account_all" in text:
                self.sub_error = text


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
    """Уведомления и команды. Отвечает только владельцу (TG_CHAT_ID).
    TG_DETAIL: full — всё; short (по умолчанию) — без размеров, цен и номеров аккаунтов; minimal — ещё и без тикеров."""

    def __init__(self, http, token: str, chat_id: str, proxy: str = "", detail: str = "short"):
        self.http, self.token, self.chat_id = http, token, chat_id
        self.proxy = proxy or None
        self.detail = detail if detail in ("full", "short", "minimal") else "short"
        self.offset = 0

    async def call(self, method: str, **params):
        if not self.token:
            return None
        import aiohttp
        async with self.http.post(f"https://{TELEGRAM_HOST}/bot{self.token}/{method}", json=params,
                                  proxy=self.proxy,
                                  timeout=aiohttp.ClientTimeout(total=params.get("timeout", 0) + 15)) as r:
            return await r.json(content_type=None)

    async def send(self, text: str) -> None:
        # в локальный лог — полностью (он остаётся на твоём компьютере), секреты всё равно вымараны
        log.info("TG: %s", redact(re.sub(r"<[^>]+>", "", strip_marks(text))))
        if not (self.token and self.chat_id):
            return
        for chunk in split_message(redact(render(text, self.detail))):
            try:
                r = await self.call("sendMessage", chat_id=self.chat_id, text=chunk, parse_mode="HTML",
                                    disable_web_page_preview=True)
                if isinstance(r, dict) and not r.get("ok"):
                    # например, HTML не разобрался — шлём простым текстом, чтобы важное сообщение не потерялось
                    log.warning("Telegram: %s", redact(str(r.get("description"))))
                    await self.call("sendMessage", chat_id=self.chat_id, disable_web_page_preview=True,
                                    text=html.unescape(re.sub(r"<[^>]+>", "", chunk)))
            except Exception as e:  # noqa: BLE001
                log.warning("Telegram: %s", redact(str(e)))

    async def poll(self, guardians: list[Guardian], hedges=()) -> None:
        if not (self.token and self.chat_id):
            return
        await self.call("setMyCommands", commands=[
            {"command": "status", "description": "Позиции и стопы"},
            {"command": "pairs", "description": "Вилки RH ↔ CORE"},
            {"command": "wallets", "description": "Кошельки и аккаунты"},
            {"command": "pause", "description": "Только алерты, без действий"},
            {"command": "resume", "description": "Снова действовать"},
        ])
        try:   # старые команды (пока страж был выключен) не выполняем
            old = await self.call("getUpdates", offset=-1, timeout=0)
            if isinstance(old, dict) and old.get("result"):
                self.offset = old["result"][-1]["update_id"] + 1
        except Exception as e:  # noqa: BLE001
            log.warning("Telegram: %s", redact(str(e)))
        warned = False
        while True:
            try:
                data = await self.call("getUpdates", offset=self.offset, timeout=30, allowed_updates=["message"])
                if isinstance(data, dict) and not data.get("ok", True):
                    log.warning("Telegram getUpdates: %s", redact(str(data.get("description"))))
                    if data.get("error_code") == 409 and not warned:
                        warned = True
                        await self.send("⚠️ Этого Telegram-бота опрашивает ещё одна программа — команды до стража "
                                        "не доходят. Создай для стража отдельного бота у @BotFather.")
                    await asyncio.sleep(15)
                    continue
                for upd in (data or {}).get("result", []):
                    self.offset = upd["update_id"] + 1
                    msg = upd.get("message") or {}
                    if str((msg.get("chat") or {}).get("id")) != str(self.chat_id):
                        continue      # чужим не отвечаем вообще
                    parts = (msg.get("text") or "").strip().split()
                    if not parts:
                        continue
                    cmd = parts[0].split("@")[0].lower()
                    # необязательный номер кошелька: /status 2, /pause 1
                    num_ = next((int(x.lstrip("#")) for x in parts[1:] if x.lstrip("#").isdigit()), None)
                    sel = [g for g in guardians if num_ is None or g.ex.wallet == num_]
                    if num_ is not None and not sel:
                        await self.send(f"Кошелька #{num_} нет. Есть: " +
                                        ", ".join(sorted({f"#{g.ex.wallet}" for g in guardians})))
                        continue
                    hs = [h for h in hedges if num_ is None or h.wallet == num_]
                    who = "всех кошельков" if num_ is None else f"кошелька #{num_}"
                    if cmd in ("/status", "/start"):
                        out = [g.status_text() for g in sel] + [h.pairs_text() for h in hs if h.pairs]
                        await self.send("\n\n".join(out))
                    elif cmd == "/pairs":
                        await self.send("\n\n".join(h.pairs_text() for h in hs) if hs else
                                        "Вилки работают, когда у кошелька подключены обе биржи: RH и CORE.")
                    elif cmd == "/wallets":
                        rows = {}
                        for g in guardians:
                            prox = getattr(g.ex, "proxy", None)
                            rows.setdefault(g.ex.wallet, []).append(
                                f"{g.ex.venue} (аккаунт {S(g.ex.account_index)}"
                                f"{', прокси ' + S(mask_proxy(prox)) if prox else ''}){' ⏸' if g.paused else ''}")
                        names = {g.ex.wallet: g.ex.wallet_name for g in guardians}
                        await self.send("👛 <b>Кошельки</b>\n" + "\n".join(
                            f"#{n}{' ' + html.escape(names[n]) if names[n] else ''}: {', '.join(v)}"
                            for n, v in sorted(rows.items())))
                    elif cmd == "/pause":
                        for g in sel:
                            g.paused = True
                        await self.send(f"⏸ Пауза для {who}: только алерты, никаких действий на бирже. "
                                        f"/resume{'' if num_ is None else ' ' + str(num_)} — вернуть.")
                    elif cmd == "/resume":
                        for g in sel:
                            g.paused = False
                        await self.send(f"▶️ Страж снова действует для {who}.")
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                log.warning("Telegram polling: %s", e)
                await asyncio.sleep(5)


def split_message(text: str, limit: int = 3900) -> list[str]:
    """Telegram принимает до 4096 символов: режем по строкам, чтобы не разрывать HTML-теги."""
    if len(text) <= limit:
        return [text]
    out, cur = [], ""
    for line in text.split("\n"):
        while len(line) > limit:
            if cur:
                out.append(cur)
                cur = ""
            out.append(line[:limit])
            line = line[limit:]
        if cur and len(cur) + 1 + len(line) > limit:
            out.append(cur)
            cur = line
        else:
            cur = f"{cur}\n{line}" if cur else line
    if cur:
        out.append(cur)
    return out


# ───────────────────────────── запуск ─────────────────────────────

def wallet_configs() -> list[dict]:
    """Кошельки W1_…, W2_…, … — на каждом можно подключить RH и/или CORE.
    Старый формат RH_* / CORE_* без номера считается кошельком №1."""
    wallets: dict[int, dict] = {}
    common_proxy = env("PROXY")

    def add(n: int, prefix: str, venue: str, default_net: str, shared_l1: str, name: str, proxy: str):
        key = env(f"{prefix}API_PRIVATE_KEY")
        if not key:
            return
        net = env(f"{prefix}NETWORK", default_net)
        if net not in NETWORKS:
            raise SystemExit(f"{prefix}NETWORK: неизвестная сеть {net}. Варианты: {', '.join(NETWORKS)}")
        acc = env(f"{prefix}ACCOUNT_INDEX")
        l1 = env(f"{prefix}L1_ADDRESS") or shared_l1
        if not acc and not l1:
            raise SystemExit(f"Кошелёк #{n}: укажи адрес W{n}_ADDRESS (или {prefix}ACCOUNT_INDEX)")
        w = wallets.setdefault(n, {"wallet": n, "name": name, "exchanges": []})
        w["exchanges"].append(dict(network=net, account_index=int(acc) if acc else None, l1_address=l1,
                                   api_key_index=int(env(f"{prefix}API_KEY_INDEX", "4")),
                                   api_private_key=key, wallet=n, wallet_name=name,
                                   proxy=env(f"{prefix}PROXY") or proxy))

    # старый формат без номера → кошелёк №1
    if env("RH_API_PRIVATE_KEY") or env("CORE_API_PRIVATE_KEY"):
        l1 = env("ADDRESS")
        add(1, "RH_", "RH", "robinhood", l1, env("NAME"), common_proxy)
        add(1, "CORE_", "CORE", "mainnet", l1, env("NAME"), common_proxy)
    numbers = sorted({int(m.group(1)) for k in env_names() if (m := re.match(r"W(\d+)_", k))})
    for n in numbers:
        if n in wallets:
            raise SystemExit(f"Кошелёк #{n} задан дважды: и через RH_/CORE_, и через W{n}_")
        l1, name = env(f"W{n}_ADDRESS"), env(f"W{n}_NAME")
        proxy = env(f"W{n}_PROXY") or common_proxy          # свой прокси кошелька, иначе общий
        add(n, f"W{n}_RH_", "RH", "robinhood", l1, name, proxy)
        add(n, f"W{n}_CORE_", "CORE", "mainnet", l1, name, proxy)
    if not wallets:
        raise SystemExit("Не задан ни один кошелёк. Создай ключи: python setup_key.py --wallet 1")
    return [wallets[n] for n in sorted(wallets)]


def load_secrets() -> None:
    """Секреты — из зашифрованного хранилища. Открытым текстом — только если явно разрешено."""
    import vault
    plain = sorted(k for k in os.environ if vault.is_secret(k) and os.environ[k].strip())
    allow_plain = env_bool("ALLOW_PLAINTEXT_SECRETS", False)
    if plain and not allow_plain:
        raise SystemExit("❌ В .env или окружении лежат секреты открытым текстом: " + ", ".join(plain) +
                         "\nПеренеси их в зашифрованное хранилище: python vault.py import .env")
    if vault.DEFAULT_PATH.exists():
        try:
            v = vault.unlock()
        except vault.VaultError as e:
            raise SystemExit(f"❌ {e}") from None
        SECRETS.update(v.data)
        log.info("Хранилище открыто: %d записей", len(v.data))
    elif not allow_plain:
        raise SystemExit("❌ Нет хранилища секретов. Создай: python vault.py init, "
                         "затем python setup_key.py --wallet 1")
    for k in env_names():
        if vault.is_secret(k):
            register_secret(env(k))


class Runner:
    """Запускает биржи независимо друг от друга: если одна не поднялась, остальные уже защищают,
    а упавшая переподключается в фоне. Все циклы переживают ошибки."""

    def __init__(self, tg: "Telegram", cfg: Config):
        self.tg, self.cfg = tg, cfg
        self.guardians: list[Guardian] = []
        self.hedges: list = []
        self.by_wallet: dict[int, list[Guardian]] = {}
        self.tasks: set[asyncio.Task] = set()

    def bg(self, coro) -> None:
        t = asyncio.create_task(coro)
        self.tasks.add(t)
        t.add_done_callback(self.tasks.discard)

    async def start_exchange(self, wallet: int, ex: "LighterExchange") -> None:
        delay, failed = 30, False
        while True:
            try:
                await ex.start()
                break
            except Exception as e:  # noqa: BLE001
                msg = redact(str(e))
                log.warning("%s: не удалось подключиться: %s", ex.label, msg)
                if not failed:
                    failed = True
                    await self.tg.send(f"❗ <b>{html.escape(ex.label)}</b>: не удалось подключиться — "
                                       f"{S(html.escape(msg))}\nПробую снова в фоне; остальные кошельки защищены.")
                await asyncio.sleep(delay)
                delay = min(delay * 2, 300)
        g = Guardian(ex, self.cfg, self.tg.send)
        ex.guardian = g
        try:
            await ex.refresh_positions()
        except Exception as e:  # noqa: BLE001
            log.warning("%s: позиции по REST: %s", ex.label, redact(str(e)))
        self.guardians.append(g)
        ex.last_msg = time.time()
        if failed:
            await self.tg.send(f"✅ <b>{html.escape(ex.label)}</b>: подключился, страж работает.")
        for coro in (ex.stream(), self.ticker(g), self.reconcile(g), self.health(g)):
            self.bg(coro)
        wg = self.by_wallet.setdefault(wallet, [])
        wg.append(g)
        # вилка ищется внутри одного кошелька: его RH ↔ его CORE
        if len(wg) == 2 and self.cfg.hedge != "off":
            from hedge import HedgeManager
            self.hedges.append(HedgeManager({x.ex.label: x for x in wg}, self.cfg, self.tg.send, wallet=wallet))

    async def ticker(self, g: Guardian) -> None:
        while True:
            try:
                g.spawn(g.tick())       # действия — в фоне: долгое закрытие не задерживает проверку остальных пар
            except Exception:  # noqa: BLE001
                log.exception("%s: проверка", g.ex.label)
            await asyncio.sleep(0.5)

    async def hedge_ticker(self) -> None:
        while True:
            for h in list(self.hedges):
                try:
                    h.spawn(h.tick())
                except Exception:  # noqa: BLE001
                    log.exception("вилка")
            await asyncio.sleep(0.25)

    async def reconcile(self, g: Guardian) -> None:
        """Раз в 30 с — сверка с биржей по REST: позиции и ордера рынков с открытыми позициями."""
        while True:
            await asyncio.sleep(30)
            try:
                await g.ex.refresh_positions()
            except Exception as e:  # noqa: BLE001
                log.warning("%s: сверка позиций: %s", g.ex.label, redact(str(e)))
            for mid in [m for m, p in g.positions.items() if p != 0]:
                try:
                    orders = await g.ex.fetch_active_orders(mid)
                except Exception as e:  # noqa: BLE001
                    log.warning("%s: сверка ордеров: %s", g.ex.label, redact(str(e)))
                    break
                if orders is not None:
                    g.spawn(g.sync_orders(mid, orders))

    async def health(self, g: Guardian) -> None:
        """Сообщает, если страж «ослеп»: нет данных от биржи или биржа не даёт подписку на ордера."""
        ex, down, seen_err = g.ex, False, ""
        while True:
            await asyncio.sleep(10)
            try:
                silent = time.time() - ex.last_msg
                if silent > 120 and not down:
                    down = True
                    await self.tg.send(f"❗ <b>{html.escape(ex.label)}</b>: нет данных от биржи уже {silent:.0f} с — "
                                       "страж сейчас не видит позиции. Переподключаюсь…")
                elif silent < 60 and down:
                    down = False
                    await self.tg.send(f"✅ <b>{html.escape(ex.label)}</b>: связь с биржей восстановлена.")
                if ex.sub_error and ex.sub_error != seen_err:
                    seen_err = ex.sub_error
                    await self.tg.send(f"❗ <b>{html.escape(ex.label)}</b>: биржа не даёт подписку на ордера "
                                       f"или позиции — {S(html.escape(ex.sub_error))}. Проверь API-ключ и время "
                                       "на компьютере (часы должны быть точными).")
                elif not ex.sub_error:
                    seen_err = ""
            except Exception:  # noqa: BLE001
                log.exception("health")


async def main_async() -> None:
    import aiohttp
    from security import SafeSession, harden_process
    for item in harden_process():
        log.info("Защита: %s", item)
    load_secrets()
    cfg = Config()
    max_runtime = env_float("MAX_RUNTIME_MIN", 0) * 60
    log.info("Разрешённые адреса: %s", ", ".join(sorted(ALLOWED_HOSTS)))
    # trust_env=False: системные переменные прокси игнорируются — только явно заданные PROXY / W{n}_PROXY
    async with aiohttp.ClientSession(trust_env=False) as raw:
        http = SafeSession(raw, ALLOWED_HOSTS)
        tg = Telegram(http, env("TG_TOKEN"), env("TG_CHAT_ID"), proxy=env("PROXY"),
                      detail=env("TG_DETAIL", "short").lower())
        runner = Runner(tg, cfg)
        exchanges = [(w["wallet"], LighterExchange(http, **c)) for w in wallet_configs() for c in w["exchanges"]]
        SECRETS.clear()             # ключи — внутри объектов бирж (до запуска) и модуля подписи; копии не нужны
        starters = [asyncio.create_task(runner.start_exchange(n, ex)) for n, ex in exchanges]
        await asyncio.wait(starters, timeout=60)          # первая попытка для всех; упавшие продолжат в фоне
        for t in starters:
            runner.tasks.add(t)
            t.add_done_callback(runner.tasks.discard)
        runner.bg(runner.hedge_ticker())
        runner.bg(tg.poll(runner.guardians, runner.hedges))
        if env_bool("STARTUP_MESSAGE", True) and runner.guardians:
            await tg.send("\n\n".join(g.status_text() for g in runner.guardians))
        forever = asyncio.Event()
        if max_runtime > 0:
            try:
                await asyncio.wait_for(forever.wait(), timeout=max_runtime)
            except asyncio.TimeoutError:
                log.info("Плановое завершение (MAX_RUNTIME_MIN)")
        else:
            await forever.wait()


def main() -> None:
    from security import install_log_redaction
    logging.basicConfig(level=env("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s",
                        stream=sys.stdout)
    install_log_redaction()
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
