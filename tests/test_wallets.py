"""Тесты нумерованных кошельков: вилки внутри кошелька и команды Telegram.  python -m tests.test_wallets"""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["DRY_RUN"] = "false"
import guardian as G  # noqa: E402
import hedge as H     # noqa: E402


class Ex:
    def __init__(self, wallet, venue, markets):
        self.wallet, self.venue, self.wallet_name = wallet, venue, ""
        self.label = f"#{wallet} {venue}"
        self.markets, self.account_index, self.sent = markets, 100 + wallet, []

    async def market_close(self, mid, size, is_ask, worst_price):
        self.sent.append((mid, size))
        return True, ""

    async def best_price(self, *a):
        return 100.0

    async def refresh_positions(self):
        pass


def build():
    msgs = []

    async def notify(t):
        msgs.append(t)
    cfg = G.Config()
    cfg.dry_run, cfg.hedge, cfg.hedge_debounce = False, "act", 0.7
    gs, hedges = [], []
    for w in (1, 2):
        wg = {}
        for venue, mid in (("RH", 15), ("CORE", 115)):
            ex = Ex(w, venue, {mid: G.Market(mid, "NVDA", 4, 2)})
            g = G.Guardian(ex, cfg, notify)
            ex.g = g
            g.on_positions({}, snapshot=True, now=0)
            wg[ex.label] = g
            gs.append(g)
        hedges.append(H.HedgeManager(wg, cfg, notify, wallet=w))
    return gs, hedges, msgs


def test_hedge_stays_inside_wallet():
    gs, hedges, msgs = build()
    rh1, core1, rh2, core2 = gs
    rh1.on_positions({15: 5.0}, now=1)       # кошелёк 1: лонг на RH
    core2.on_positions({115: -5.0}, now=1)   # кошелёк 2: шорт на CORE — это НЕ вилка с кошельком 1
    for h in hedges:
        h.tick(now=2)
    assert all(not h.pairs for h in hedges)
    core1.on_positions({115: -5.0}, now=3)   # а вот это вилка кошелька 1
    acts = [a for h in hedges for a in h.tick(now=4)]
    assert len(hedges[0].pairs) == 1 and not hedges[1].pairs
    assert "NVDA·#1 RH" in acts[0][1] and "NVDA·#1 CORE" in acts[0][1]
    print("1. вилка ищется только внутри своего кошелька ✓")


def test_telegram_commands():
    gs, hedges, msgs = build()
    tg = G.Telegram(None, "token", "777")
    sent = []

    async def fake_send(t):
        sent.append(t)
    tg.send = fake_send
    texts = iter(["/pause 2", "/status 1", "/wallets", "/resume", "/status 9", "/pairs 1"])

    async def fake_call(method, **p):
        if method != "getUpdates":
            return {"ok": True}
        try:
            t = next(texts)
        except StopIteration:
            raise asyncio.CancelledError
        return {"result": [{"update_id": 1, "message": {"chat": {"id": 777}, "text": t}}]}
    tg.call = fake_call
    try:
        asyncio.run(tg.poll(gs, hedges))
    except asyncio.CancelledError:
        pass
    assert [g.paused for g in gs] == [False, False, False, False]          # /resume снял всё
    assert "кошелька #2" in sent[0]
    assert "#1 RH" in sent[1] and "#2" not in sent[1]                      # /status 1 — только кошелёк 1
    assert "#1:" in sent[2] and "#2:" in sent[2]                           # /wallets
    assert "Кошелька #9 нет" in sent[4]
    assert "Кошелёк #1" in sent[5] and "#2" not in sent[5]
    print("2. /pause N, /status N, /wallets, /pairs N работают по номеру кошелька ✓")


def test_pause_one_wallet_only():
    gs, hedges, msgs = build()
    for g in gs:
        if g.ex.wallet == 2:
            g.paused = True
    assert gs[0].mode("soft_stop") == "act" and gs[2].mode("soft_stop") == "alert"
    print("3. пауза одного кошелька не трогает другие ✓")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
    print("\nВСЕ ТЕСТЫ КОШЕЛЬКОВ ПРОЙДЕНЫ")
