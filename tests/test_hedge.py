"""Тесты вилки RH ↔ CORE на симулированных биржах.  Запуск: python -m tests.test_hedge"""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["DRY_RUN"] = "false"
import guardian as G  # noqa: E402
import hedge as H     # noqa: E402


class Ex:
    def __init__(self, label, markets):
        self.label, self.markets = label, markets
        self.g = None
        self.sent = []
        self.fill = True

    async def market_close(self, mid, size, is_ask, worst_price):
        self.sent.append((mid, size, is_ask, round(worst_price, 3)))
        if self.fill:
            cur = self.g.positions.get(mid, 0.0)
            new = round(cur - size if cur > 0 else cur + size, 6)
            self.g.on_positions({mid: new})
        return True, ""

    async def best_price(self, mid, is_ask):
        return 100.0

    async def cancel_order(self, mid, idx):
        return True, ""

    async def refresh_positions(self):
        pass


def setup(dry=False, mode="act", debounce=0.7):
    msgs = []

    async def notify(t):
        msgs.append(G.strip_marks(t))
    cfg = G.Config()
    cfg.dry_run, cfg.hedge, cfg.hedge_debounce = dry, mode, debounce
    rh = Ex("RH", {15: G.Market(15, "NVDA", 4, 2), 37: G.Market(37, "SKHY", 4, 2)})
    core = Ex("CORE", {115: G.Market(115, "NVDA", 3, 3), 143: G.Market(143, "SKHYNIX", 3, 4),
                       117: G.Market(117, "META", 3, 2)})
    gs = {}
    for ex in (rh, core):
        g = G.Guardian(ex, cfg, notify)
        ex.g = g
        g.on_positions({}, snapshot=True, now=0)
        g.on_quote(next(iter(ex.markets)), 200.0, 200.1, 200.0, now=1e12)
        for mid in ex.markets:
            g.on_quote(mid, 200.0, 200.1, 200.0, now=1e12)
        gs[ex.label] = g
    hm = H.HedgeManager(gs, cfg, notify)
    return hm, gs, rh, core, msgs


def go(hm, now):
    acts = hm.tick(now=now)
    asyncio.run(hm.run_actions(acts))
    return acts


def test_auto_pair_and_close():
    hm, gs, rh, core, msgs = setup()
    gs["RH"].on_positions({15: 10.0}, now=1)          # лонг NVDA на RH
    gs["CORE"].on_positions({115: -10.0}, now=1)      # шорт NVDA на CORE
    gs["CORE"].on_positions({117: 3.0}, now=1)        # META только на CORE — не вилка
    go(hm, 2)
    assert len(hm.pairs) == 1 and "Вижу вилку" in msgs[-1]
    assert gs["RH"].hedged == {15} and gs["CORE"].hedged == {115}
    # стоп на RH: лонг закрылся
    gs["RH"].on_positions({15: 0.0}, now=10)
    assert go(hm, 10.3) == []                         # увидели изменение — ждём debounce
    assert go(hm, 10.8) == []
    go(hm, 11.1)
    assert core.sent == [(115, 10.0, False, round(200.1 * 1.01, 3))], core.sent
    assert gs["CORE"].positions[115] == 0 and "✅" in msgs[-1]
    go(hm, 11.5)
    assert hm.pairs == []                             # вилка закончилась
    assert rh.sent == []                              # и зеркально ничего не дёргали
    print("1. нога закрылась по стопу → вторая закрыта, вилка снята ✓")


def test_partial_reduce_proportional():
    hm, gs, rh, core, msgs = setup()
    gs["RH"].on_positions({15: -8.0}, now=1)          # шорт RH
    gs["CORE"].on_positions({115: 8.4}, now=1)        # лонг CORE (размеры чуть разные)
    go(hm, 2)
    # частичное исполнение тейка на RH кусками: -8 → -6 → -2
    gs["RH"].on_positions({15: -6.0}, now=5)
    go(hm, 5.2)
    gs["RH"].on_positions({15: -2.0}, now=5.4)
    go(hm, 5.6)
    assert core.sent == []                            # ждём, пока куски закончатся
    go(hm, 6.4)
    # осталось 25% → на CORE должно остаться 8.4 * 0.25 = 2.1
    assert core.sent[0][:3] == (115, 6.3, True), core.sent
    assert abs(gs["CORE"].positions[115] - 2.1) < 1e-9
    go(hm, 7)
    go(hm, 8)
    assert len(core.sent) == 1 and rh.sent == []      # наша подрезка не вызвала встречную подрезку RH
    print("2. частичная подрезка пропорционально (с учётом кусков) и без зацикливания ✓")


def test_add_and_aliases():
    hm, gs, rh, core, msgs = setup()
    gs["RH"].on_positions({37: 5.0}, now=1)           # SKHY на RH
    gs["CORE"].on_positions({143: -5.0}, now=1)       # SKHYNIX на CORE — та же акция
    go(hm, 2)
    assert len(hm.pairs) == 1
    gs["RH"].on_positions({37: 7.0}, now=3)           # доливка
    go(hm, 4)
    go(hm, 5)
    assert core.sent == [] and hm.pairs[0].sync[("RH", 37)] == 7.0
    gs["RH"].on_positions({37: 3.5}, now=5.5)         # закрыл половину
    go(hm, 6)
    go(hm, 7)
    assert core.sent[0][:3] == (143, 2.5, False), core.sent   # 5 * 0.5 → подрезать 2.5
    print("3. доливка запоминается, SKHY ↔ SKHYNIX — одна акция ✓")


def test_same_direction_not_paired():
    hm, gs, rh, core, msgs = setup()
    gs["RH"].on_positions({15: 1.0}, now=1)
    gs["CORE"].on_positions({115: 1.0}, now=1)        # оба лонга — это не вилка
    go(hm, 2)
    assert hm.pairs == []
    print("4. одинаковое направление — не вилка ✓")


def test_dry_run_and_alert():
    hm, gs, rh, core, msgs = setup(dry=True)
    gs["RH"].on_positions({15: 10.0}, now=1)
    gs["CORE"].on_positions({115: -10.0}, now=1)
    go(hm, 2)
    gs["RH"].on_positions({15: 0.0}, now=3)
    go(hm, 4)
    go(hm, 5)
    assert core.sent == [] and "DRY_RUN" in msgs[-1] and "Закрываю" in msgs[-1]
    go(hm, 5)
    go(hm, 6)
    assert sum("DRY_RUN" in m for m in msgs) == 1     # не спамит каждую секунду
    hm2, gs2, rh2, core2, msgs2 = setup(mode="alert")
    gs2["RH"].on_positions({15: 10.0}, now=1)
    gs2["CORE"].on_positions({115: -10.0}, now=1)
    go(hm2, 2)
    gs2["CORE"].on_positions({115: -5.0}, now=3)
    go(hm2, 4)
    go(hm2, 5)
    assert rh2.sent == [] and "только алерт" in msgs2[-1] and "+10 → +5" in msgs2[-1], msgs2[-1]
    print("5. DRY_RUN и режим «только алерт»: ничего не отправляется, одно сообщение ✓")


def test_both_closed_manually():
    hm, gs, rh, core, msgs = setup()
    gs["RH"].on_positions({15: 10.0}, now=1)
    gs["CORE"].on_positions({115: -10.0}, now=1)
    go(hm, 2)
    gs["RH"].on_positions({15: 0.0}, now=3)
    gs["CORE"].on_positions({115: 0.0}, now=3.2)      # пользователь сам закрыл обе ноги
    go(hm, 4)
    go(hm, 5)
    assert core.sent == [] and rh.sent == [] and hm.pairs == []
    print("6. обе ноги закрыл сам — ничего лишнего не отправлено ✓")


def test_naked_suppressed_for_hedge():
    hm, gs, rh, core, msgs = setup()
    gs["RH"].on_positions({15: 10.0}, now=1)
    gs["CORE"].on_positions({115: -10.0}, now=1)
    go(hm, 2)
    acts = gs["RH"].tick(now=1000)
    assert not any("без стоп-лосса" in str(a) for a in acts)
    print("7. ноги вилки без стопа не считаются «голыми» ✓")


def test_ten_second_pause():
    assert G.Config().hedge_debounce == 3                 # по умолчанию — 3 секунды
    hm, gs, rh, core, msgs = setup(debounce=10)
    gs["RH"].on_positions({15: 10.0}, now=1)
    gs["CORE"].on_positions({115: -10.0}, now=1)
    go(hm, 2)
    gs["RH"].on_positions({15: 0.0}, now=20)          # стоп на RH
    assert go(hm, 20.1) == [] and go(hm, 25) == [] and go(hm, 30.0) == [] and core.sent == []
    go(hm, 30.2)
    assert core.sent and core.sent[0][:2] == (115, 10.0), core.sent
    # вторая нога закрылась сама за время паузы — страж её не трогает
    hm, gs, rh, core, msgs = setup(debounce=10)
    gs["RH"].on_positions({15: 10.0}, now=1)
    gs["CORE"].on_positions({115: -10.0}, now=1)
    go(hm, 2)
    gs["RH"].on_positions({15: 0.0}, now=20)          # стоп на RH
    go(hm, 21)
    gs["CORE"].on_positions({115: 0.0}, now=24)       # через 4 с сработал тейк на CORE
    for t in (25, 31, 35, 40):
        go(hm, t)
    assert core.sent == [] and rh.sent == [], (core.sent, rh.sent)
    print("8. пауза 10 с перед закрытием второй ноги; закрылась сама — не трогаем ✓")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
    print("\nВСЕ ТЕСТЫ ВИЛКИ ПРОЙДЕНЫ")
