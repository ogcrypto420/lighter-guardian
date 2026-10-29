"""Тесты логики стража на симулированной бирже (без сети и без ключей).
Запуск: python -m tests.test_guardian   (из папки проекта)"""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["DRY_RUN"] = "false"
import guardian as G  # noqa: E402


class FakeExchange:
    label = "RH"

    def __init__(self):
        self.markets = {15: G.Market(15, "NVDA", 4, 2), 42: G.Market(42, "OPENAI", 4, 2)}
        self.cancelled, self.closes = [], []
        self.fill_close = True          # исполнится ли рыночное закрытие
        self.fail_first = 0             # сколько первых попыток закрытия «не исполнится»
        self.g = None

    async def cancel_order(self, mid, idx):
        self.cancelled.append((mid, idx))
        return True, ""

    async def best_price(self, mid, is_ask):
        # как стакан по REST: лучшая цена из последней котировки
        q = self.g.quotes.get(mid) if self.g else None
        return (q.bid if is_ask else q.ask) if q else 100.0

    async def market_close(self, mid, size, is_ask, worst_price):
        self.closes.append((mid, size, is_ask, round(worst_price, 4)))
        if self.fill_close and len(self.closes) > self.fail_first:
            # биржа присылает обновление позиции
            self.g.on_positions({mid: 0.0})
        return True, ""

    async def refresh_positions(self):
        pass


def make(cfg=None):
    ex = FakeExchange()
    sent = []

    async def notify(t):
        sent.append(G.strip_marks(t))
    c = cfg or G.Config()
    c.dry_run = False
    c.cleanup = c.failed_stop = c.soft_stop = "act"
    c.cleanup_delay, c.soft_stop_seconds, c.naked_alert_min = 1.5, 5, 2
    g = G.Guardian(ex, c, notify)
    ex.g = g
    g.on_positions({}, snapshot=True, now=0)     # стартовый снимок: позиций нет
    return g, ex, sent


def order(idx, mid, typ, status="open", is_ask=True, ro=True, trig=0.0, price=0.0, ts="ready"):
    return G.Order(idx, mid, typ, status, is_ask, ro, price, trig, 1.0, ts)


def run(coro):
    return asyncio.run(coro)


def test_cleanup_after_stop():
    g, ex, sent = make()
    g.on_positions({15: 2.0}, now=10)                                   # лонг NVDA
    g.on_orders([order(1, 15, "stop-loss", trig=210), order(2, 15, "take-profit", trig=230),
                 order(3, 42, "take-profit", trig=1500)], snapshot=True)
    # стоп сработал: SL исполнился, позиция 0, TP остался висеть
    g.on_orders([order(1, 15, "stop-loss", status="filled", trig=210)])
    g.on_positions({15: 0.0}, now=20)
    assert g.tick(now=20.5) == []                                        # ждём cleanup_delay
    acts = g.tick(now=21.6)
    assert [a[0] for a in acts] == ["cleanup"] and [o.index for o in acts[0][2]] == [2]
    run(g.run_actions(acts))
    assert ex.cancelled == [(15, 2)], ex.cancelled                       # ордер другой пары не тронут
    assert "отменил висящие" in sent[-1] and "TP 230" in sent[-1]
    print("1. висящий TP после стопа отменён ✓")


def test_cleanup_keeps_entry_orders():
    g, ex, sent = make()
    g.on_positions({15: 2.0}, now=0)
    g.on_orders([
        order(1, 15, "take-profit", trig=230),                              # защитный TP лонга
        order(2, 15, "stop-loss", is_ask=False, ro=False, trig=240),        # стоп-вход в шорт? нет — покупка: вход на пробой
        order(3, 15, "limit", is_ask=False, ro=False, price=200),            # лимитка на вход
        order(4, 15, "stop-loss", trig=190, ts="parent-order"),             # ждёт родителя (OTOCO) — не трогаем
    ], snapshot=True)
    g.on_positions({15: 0.0}, now=10)
    acts = g.tick(now=12)
    assert [o.index for o in acts[0][2]] == [1], [o.index for o in acts[0][2]]
    print("1b. входные ордера и ордера с родителем не трогаются ✓")


def test_no_cleanup_if_reopened():
    g, ex, sent = make()
    g.on_positions({15: 2.0}, now=0)
    g.on_orders([order(1, 15, "take-profit", trig=230)], snapshot=True)
    g.on_positions({15: 0.0}, now=10)
    g.on_positions({15: 1.0}, now=10.5)       # сразу открыл новую позицию
    assert g.tick(now=12) == []
    print("1c. если позицию сразу переоткрыли — ничего не отменяем ✓")


def test_failed_stop_emergency_close():
    g, ex, sent = make()
    g.on_positions({42: -3.0}, now=0)                                   # шорт OPENAI
    g.on_quote(42, 1189.0, 1191.0, 1190.0, now=0)
    g.on_orders([order(7, 42, "stop-loss", is_ask=False, trig=1250)], snapshot=True)
    acts = g.on_orders([order(7, 42, "stop-loss", status="canceled-too-much-slippage", is_ask=False, trig=1250)])
    assert acts[0][0] == "emergency"
    run(g.run_actions(acts))
    mid, size, is_ask, worst = ex.closes[0]
    assert (mid, size, is_ask) == (42, 3.0, False) and worst == round(1191.0 * 1.01, 4), ex.closes
    assert "проскальзывание" in sent[0] and "позиция закрыта" in sent[-1]
    print("2. стоп отменён биржей → позиция закрыта рыночной ✓")


def test_failed_tp_only_alert():
    g, ex, sent = make()
    g.on_positions({15: 2.0}, now=0)
    acts = g.on_orders([order(9, 15, "take-profit", status="canceled-not-enough-liquidity", trig=230)])
    assert acts[0][0] == "alert"
    run(g.run_actions(acts))
    assert ex.closes == [] and "нет ликвидности" in sent[-1]
    print("2b. отменённый TP — только предупреждение, позицию не трогаем ✓")


def test_soft_stop():
    g, ex, sent = make()
    g.on_positions({15: 2.0}, now=0)
    g.on_orders([order(1, 15, "stop-loss-limit", trig=210, price=209.9)], snapshot=True)
    g.on_quote(15, 209.0, 209.2, 211.0, now=100)     # bid под стопом, mark ещё выше
    assert g.tick(now=100) == []
    g.on_quote(15, 209.5, 209.6, 211.0, now=103)
    assert g.tick(now=103) == []
    g.on_quote(15, 209.4, 209.6, 210.8, now=105.1)
    acts = g.tick(now=105.1)
    assert acts and acts[0][0] == "emergency" and "mark 210.8" in G.strip_marks(acts[0][2]), acts
    run(g.run_actions(acts))
    assert ex.closes[0][:3] == (15, 2.0, True) and ex.closes[0][3] == round(209.4 * 0.99, 4)
    print("3. цена за стопом 5 с, стоп не исполнился → закрыто ✓")


def test_soft_stop_wick_ignored():
    g, ex, sent = make()
    g.on_positions({15: 2.0}, now=0)
    g.on_orders([order(1, 15, "stop-loss", trig=210)], snapshot=True)
    g.on_quote(15, 209.0, 209.2, 210.5, now=100)
    g.tick(now=100)
    g.on_quote(15, 211.0, 211.1, 211.0, now=102)      # шпилька: цена вернулась
    g.tick(now=102)
    g.on_quote(15, 209.0, 209.1, 210.5, now=104)
    assert g.tick(now=106) == []                       # отсчёт начался заново
    g.on_quote(15, 210.0, 210.1, 210.5, now=106)
    assert g.tick(now=106) == []                       # 210.0 > 210*(1-0.05%) — в пределах буфера
    print("3b. кратковременная шпилька и касание в пределах буфера игнорируются ✓")


def test_retry_and_give_up():
    g, ex, sent = make()
    g.on_positions({15: 2.0}, now=0)
    g.on_quote(15, 200.0, 200.1, 200.0, now=time_now())
    ex.fill_close = False
    run(g.emergency_close(15, "тест", "act"))
    assert len(ex.closes) == 3 and [c[3] for c in ex.closes] == [198.0, 196.0, 194.0], ex.closes
    assert "НЕ удалось" in sent[-1]
    g2, ex2, sent2 = make()
    g2.on_positions({15: 2.0}, now=0)
    g2.on_quote(15, 200.0, 200.1, 200.0, now=time_now())
    ex2.fail_first = 1
    run(g2.emergency_close(15, "тест", "act"))
    assert len(ex2.closes) == 2 and "попытка 2" in sent2[-1]
    print("2c. повтор с растущим допуском, при неудаче — громкий алерт ✓")


def time_now():
    import time
    return time.time()


def test_naked_alert_once():
    g, ex, sent = make()
    g.on_positions({15: 2.0}, now=0)
    assert g.tick(now=0) == []
    acts = g.tick(now=121)
    assert acts and acts[0][0] == "alert" and "без стоп-лосса" in acts[0][2]
    assert g.tick(now=200) == []                        # повторно не шлём
    g2, *_ = make()
    g2.on_positions({15: 2.0}, tied={15: 2}, now=0)
    assert g2.tick(now=500) == []                       # есть position-tied TP/SL — всё ок
    print("4. позиция без стопа — одно предупреждение; tied-стопы считаются ✓")


def test_dry_run_and_pause():
    cfg = G.Config()
    g, ex, sent = make(cfg)
    g.cfg.dry_run = True
    g.on_positions({15: 2.0}, now=0)
    run(g.emergency_close(15, "тест", "act"))
    assert ex.closes == [] and "DRY_RUN" in sent[-1]
    g.cfg.dry_run = False
    g.paused = True
    acts = [("emergency", 15, "тест", "soft_stop")]
    run(g.run_actions(acts))
    assert ex.closes == [] and "только алерт" in sent[-1]
    g.paused = False
    g.cfg.soft_stop = "off"
    run(g.run_actions(acts))
    assert ex.closes == []
    print("5. DRY_RUN, пауза и выключенный сценарий — ничего не отправляется ✓")


def test_rest_does_not_override_ws():
    g, ex, sent = make()
    g.on_positions({15: 2.0}, now=0)
    g.on_positions({15: 0.0}, now=10)                                 # WS: закрыто
    g.on_positions({15: 2.0}, snapshot=True, now=12, source="rest")   # REST отстаёт
    assert g.positions[15] == 0.0 and 15 in g.pending_cleanup
    g.on_positions({15: 0.0}, snapshot=True, now=40, source="rest")
    print("6. устаревший REST не перебивает свежий WebSocket ✓")


def test_parse():
    pos, tied = G.parse_positions({"15": {"market_id": 15, "sign": -1, "position": "3.5",
                                          "position_tied_order_count": 2}})
    assert pos == {15: -3.5} and tied == {15: 2}
    o = G.Order.parse({"order_index": 5, "market_index": 15, "type": "stop-loss", "status": "open",
                       "is_ask": True, "reduce_only": True, "price": "209.90", "trigger_price": "210.00",
                       "remaining_base_amount": "2.0", "trigger_status": "mark-price"})
    assert o.trigger_price == 210 and o.closes(2.0) and not o.closes(-2.0)
    print("7. разбор позиций и ордеров из формата Lighter ✓")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
    print("\nВСЕ ТЕСТЫ ПРОЙДЕНЫ")
