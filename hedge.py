"""
Хедж-режим (вилка): одна и та же акция в противоположные стороны на Lighter RH и основном Lighter (CORE).

  • Одна нога закрылась (стоп, тейк, ликвидация, вручную) → вторая закрывается рыночной reduce-only заявкой.
  • Одна нога уменьшилась → вторая подрезается в той же пропорции.
  • Нога увеличилась (доливка) → ничего не делаем, запоминаем новый размер.

Пары находятся сами: тот же тикер на RH и CORE, лонг на одной и шорт на другой.
"""
from __future__ import annotations

import asyncio
import html
import logging
import math
import time
from dataclasses import dataclass, field

from security import S, T

log = logging.getLogger("guardian.hedge")

# одна и та же акция под разными тикерами на RH и CORE
ALIASES = {"SKHYNIX": "SKHY", "SPACEX": "SPCX"}


def base_symbol(sym: str) -> str:
    s = sym.upper()
    return ALIASES.get(s, s)


Leg = tuple  # (биржа, market_id)


@dataclass
class Pair:
    a: Leg
    b: Leg
    sign: dict = field(default_factory=dict)          # leg -> +1 лонг / −1 шорт на момент связки
    sync: dict = field(default_factory=dict)          # leg -> размер (по модулю), от которого считаем пропорцию
    seen: dict = field(default_factory=dict)          # leg -> последний увиденный размер со знаком
    changed_at: dict = field(default_factory=dict)    # leg -> когда размер последний раз менялся
    expected: dict = field(default_factory=dict)      # leg -> (целевой размер, до какого времени) — наши заявки

    def legs(self):
        return (self.a, self.b)

    def other(self, leg: Leg) -> Leg:
        return self.b if leg == self.a else self.a


class HedgeManager:
    def __init__(self, guardians: dict, cfg, notify, wallet: int = 1):
        self.g = guardians            # подпись биржи кошелька ("#1 RH" / "#1 CORE") -> Guardian
        self.wallet = wallet
        self.cfg = cfg
        self.notify = notify
        self.pairs: list[Pair] = []
        self._bg: set = set()

    # ---------- вспомогательное ----------
    def pos(self, leg: Leg) -> float:
        g = self.g.get(leg[0])
        return g.positions.get(leg[1], 0.0) if g else 0.0

    def name(self, leg: Leg) -> str:
        g = self.g.get(leg[0])
        m = g.ex.markets.get(leg[1]) if g else None
        return f"{T(html.escape(str(m.symbol if m else leg[1])))}·{html.escape(leg[0])}"

    def in_pair(self, leg: Leg) -> Pair | None:
        return next((p for p in self.pairs if leg in p.legs()), None)

    def mode(self) -> str:
        m = self.cfg.hedge
        return "alert" if (m == "act" and any(g.paused for g in self.g.values())) else m

    def pairs_text(self) -> str:
        if not self.pairs:
            return f"🔗 Кошелёк #{self.wallet}: вилок нет. Один тикер в разные стороны на RH и CORE свяжется сам."
        lines = [f"🔗 <b>Вилки кошелька #{self.wallet}</b>"]
        for p in self.pairs:
            lines.append(f"<b>{self.name(p.a)}</b> {S(f'{self.pos(p.a):+g}')} ↔ "
                         f"<b>{self.name(p.b)}</b> {S(f'{self.pos(p.b):+g}')}")
        return "\n".join(lines)

    # ---------- основная проверка ----------
    def tick(self, now: float | None = None) -> list[tuple]:
        now = time.time() if now is None else now
        if self.cfg.hedge == "off" or len(self.g) < 2:
            return []
        actions: list[tuple] = []
        self._find_pairs(actions)
        for p in list(self.pairs):
            for leg in p.legs():
                cur = self.pos(leg)
                if cur != p.seen.get(leg):
                    p.seen[leg] = cur
                    p.changed_at[leg] = now
                # изменение, которое вызвали наши же заявки, — не зеркалим
                exp = p.expected.get(leg)
                if exp:
                    target, until = exp
                    if abs(cur) <= target * 1.0001 + 1e-12 or now > until:
                        p.expected.pop(leg, None)
                        p.sync[leg] = abs(cur)
                    continue
                if now - p.changed_at.get(leg, 0) < self.cfg.hedge_debounce:
                    continue          # даём частичным исполнениям закончиться
                sync = p.sync.get(leg, 0.0)
                flipped = cur != 0 and (cur > 0) != (p.sign[leg] > 0)
                if not flipped and abs(cur) == sync:
                    continue
                other = p.other(leg)
                ocur = self.pos(other)
                if cur == 0 or flipped:
                    target, why = 0.0, "закрылась" if cur == 0 else "перевернулась"
                elif abs(cur) < sync:
                    ratio = abs(cur) / sync
                    target, why = p.sync.get(other, abs(ocur)) * ratio, f"уменьшилась на {(1 - ratio) * 100:.0f}%"
                else:
                    p.sync[leg] = abs(cur)        # доливка — просто запоминаем
                    continue
                p.sync[leg] = abs(cur)
                if ocur == 0 or abs(ocur) - target <= abs(ocur) * 1e-6:
                    p.sync[other] = abs(ocur)
                    continue
                p.expected[other] = (target, now + 20)
                actions.append(("reduce", p, leg, other, abs(ocur) - target, target, why))
            # нога закрылась и мы на это уже отреагировали — вилка закончилась
            done = any(self.pos(l) == 0 and p.sync.get(l) == 0 for l in p.legs())
            if done and not p.expected:
                self.pairs.remove(p)
        # ноги вилки без стопа — это нормально, не предупреждаем о них
        for ex, g in self.g.items():
            g.hedged = {l[1] for p in self.pairs for l in p.legs() if l[0] == ex}
        return actions

    def _find_pairs(self, actions: list) -> None:
        open_legs = []
        for ex, g in self.g.items():
            for mid, pos in g.positions.items():
                m = g.ex.markets.get(mid)
                if pos != 0 and m:
                    open_legs.append(((ex, mid), base_symbol(m.symbol), pos))
        for i, (la, sa, pa) in enumerate(open_legs):
            if self.in_pair(la):
                continue
            for lb, sb, pb in open_legs[i + 1:]:
                if lb[0] != la[0] and sb == sa and (pa > 0) != (pb > 0) and not self.in_pair(lb):
                    p = Pair(la, lb, sign={la: 1.0 if pa > 0 else -1.0, lb: 1.0 if pb > 0 else -1.0},
                             sync={la: abs(pa), lb: abs(pb)}, seen={la: pa, lb: pb})
                    self.pairs.append(p)
                    actions.append(("note", f"🔗 Вижу вилку: <b>{self.name(la)}</b> {S(f'{pa:+g}')} ↔ "
                                            f"<b>{self.name(lb)}</b> {S(f'{pb:+g}')}. Если одна нога закроется "
                                            "или уменьшится — подрежу вторую."))
                    break

    # ---------- исполнение ----------
    def spawn(self, actions: list[tuple]) -> None:
        if not actions:
            return
        t = asyncio.ensure_future(self.run_actions(actions))
        self._bg.add(t)
        t.add_done_callback(self._bg.discard)

    async def run_actions(self, actions: list[tuple]) -> None:
        for act in actions:
            try:
                if act[0] == "note":
                    await self.notify(act[1])
                elif act[0] == "reduce":
                    await self.reduce(*act[1:])
            except Exception as e:  # noqa: BLE001
                log.exception("hedge action")
                from security import redact
                await self.notify(f"❗ Вилка: ошибка — {S(html.escape(redact(str(e))))}")

    async def reduce(self, p: Pair, leg: Leg, other: Leg, delta: float, target: float, why: str) -> None:
        g = self.g[other[0]]
        ex = g.ex
        m = ex.markets[other[1]]
        step = 10 ** -m.size_decimals
        ocur = self.pos(other)
        full = target == 0
        size = abs(ocur) if full else round(math.floor(delta / step + 1e-9) * step, m.size_decimals)
        after = 0.0 if full else (abs(ocur) - size) * (1 if ocur > 0 else -1)
        head = (f"⚖️ <b>{self.name(leg)}</b> {why} (теперь {S(f'{self.pos(leg):+g}')}).\n"
                f"{'Закрываю' if full else 'Подрезаю'} вторую ногу <b>{self.name(other)}</b>: "
                f"{S(f'{ocur:+g} → {after:+g}')}")
        if size <= 0:
            p.expected.pop(other, None)
            p.sync[other] = abs(ocur)
            await self.notify(head + "\n(изменение меньше минимального шага размера — пропускаю)")
            return
        mode = self.mode()
        if mode != "act" or self.cfg.dry_run:
            p.expected.pop(other, None)
            p.sync[other] = abs(ocur)
            pre = "👀 <b>[только алерт]</b> " if mode != "act" else "🧪 <b>[DRY_RUN — ничего не отправлено]</b> "
            await self.notify(pre + head)
            return
        await self.notify(head)
        tries = max(1, self.cfg.emergency_tries)
        for attempt in range(1, tries + 1):
            ocur = self.pos(other)
            remaining = abs(ocur) - target
            if ocur == 0 or remaining <= step / 2:
                break
            send = abs(ocur) if full else round(math.floor(remaining / step + 1e-9) * step, m.size_decimals)
            if send <= 0:
                break
            slip = self.cfg.emergency_slippage_pct * attempt / 100
            ref = await g.close_ref(other[1], is_ask=ocur > 0)
            if not ref:
                raise RuntimeError(f"нет цены в стакане {self.name(other)} — закрывать вслепую не буду, сделай вручную")
            worst = ref * (1 - slip) if ocur > 0 else ref * (1 + slip)
            ok, err = await ex.market_close(other[1], send, is_ask=ocur > 0, worst_price=worst)
            if not ok:
                log.warning("hedge reduce %s попытка %d: %s", self.name(other), attempt, err)
            for _ in range(16):
                await asyncio.sleep(0.25)
                if abs(self.pos(other)) <= target + step / 2:
                    break
            if abs(self.pos(other)) > target + step / 2:
                await ex.refresh_positions()
            if abs(self.pos(other)) <= target + step / 2:
                await self.notify(f"✅ <b>{self.name(other)}</b>: теперь {S(f'{self.pos(other):+g}')} "
                                  f"(попытка {attempt}, допуск {slip * 100:g}%)")
                return
        if abs(self.pos(other)) > target + step / 2:
            await self.notify(f"❗❗ <b>{self.name(other)}</b>: не удалось {'закрыть' if full else 'подрезать'} "
                              f"за {tries} попыток, сейчас {S(f'{self.pos(other):+g}')}, нужно {S(f'{target:g}')}. "
                              "Сделай вручную!")
