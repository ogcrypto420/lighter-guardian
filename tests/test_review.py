"""Тесты на ошибки, найденные при проверке стража (каждая — отдельный сценарий).
Запуск: python -m tests.test_review"""
import asyncio
import os
import sys
import time
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
try:
    import aiohttp  # noqa: F401
except ImportError:   # для тестов без установленных зависимостей
    sys.modules["aiohttp"] = types.SimpleNamespace(ClientTimeout=lambda **k: None)
os.environ["DRY_RUN"] = "false"
import guardian as G  # noqa: E402
import hedge as HG    # noqa: E402


def run(coro):
    return asyncio.run(coro)


class Ex:
    label = "#1 Основной & Ко RH"

    def __init__(self):
        self.markets = {15: G.Market(15, "NVDA", 4, 2)}
        self.closes, self.cancelled = [], []
        self.book = None            # что вернёт «стакан по REST»
        self.g = None
        self.fill = True

    async def best_price(self, mid, is_ask):
        if isinstance(self.book, Exception):
            raise self.book
        return self.book or 0.0

    async def market_close(self, mid, size, is_ask, worst_price):
        self.closes.append((mid, size, is_ask, round(worst_price, 4)))
        if self.fill:
            self.g.on_positions({mid: 0.0})
        return True, ""

    async def cancel_order(self, mid, idx):
        self.cancelled.append(idx)
        return True, ""

    async def refresh_positions(self):
        pass


def make(dry=False):
    ex, sent = Ex(), []

    async def notify(t):
        sent.append(G.strip_marks(t))
    cfg = G.Config()
    cfg.dry_run = dry
    cfg.cleanup = cfg.failed_stop = cfg.soft_stop = "act"
    cfg.soft_stop_seconds, cfg.retry_pause_sec = 5, 60
    g = G.Guardian(ex, cfg, notify)
    ex.g = g
    g.on_positions({}, snapshot=True, now=0)
    return g, ex, sent


def sl(idx, trig, is_ask=True, status="open"):
    return G.Order(idx, 15, "stop-loss", status, is_ask, True, 0.0, trig, 1.0, "mark-price")


def test_ws_readonly():
    for net, (rest, ws, *_ ) in G.NETWORKS.items():
        assert ws.endswith("/stream?readonly=true"), (net, ws)
    print("1. WebSocket — в режиме readonly (без него Lighter отвечает 400) ✓")


def test_soft_stop_one_sided_hole_ignored():
    g, ex, sent = make()
    g.on_positions({15: 2.0}, now=0)
    g.on_orders([sl(1, 210)], snapshot=True)
    # bid провалился под стоп, но середина стакана выше стопа — это «дыра» в тонком стакане, не пробой
    for t in (100, 103, 106, 110):
        g.on_quote(15, 209.0, 213.0, 211.0, now=t)
        assert g.tick(now=t) == [], t
    print("2. мягкий стоп: «дыра» только на стороне bid пробоем не считается ✓")


def test_soft_stop_wide_book_only_alerts():
    g, ex, sent = make()
    g.on_positions({15: 2.0}, now=0)
    g.on_orders([sl(1, 210)], snapshot=True)
    g.on_quote(15, 200.0, 207.0, 205.0, now=100)        # всё за стопом, но спред 3.4%
    g.tick(now=100)
    acts = g.tick(now=105.5)
    assert [a[0] for a in acts] == ["alert"] and "слишком широкий" in acts[0][2], acts
    assert g.tick(now=120) == []                        # повторно не пишем
    print("3. мягкий стоп при широком стакане — только предупреждение, без закрытия ✓")


def test_soft_stop_no_spam_in_dry_run():
    g, ex, sent = make(dry=True)
    g.on_positions({15: 2.0}, now=0)
    g.on_orders([sl(1, 210)], snapshot=True)
    fired = 0
    for t in range(100, 160):
        g.on_quote(15, 209.0, 209.2, 209.5, now=t)
        fired += sum(1 for a in g.tick(now=t) if a[0] == "emergency")
    assert fired == 1, fired
    # цена вернулась и снова пробила — новое предупреждение
    g.on_quote(15, 212.0, 212.1, 212.0, now=161)
    g.tick(now=161)
    for t in range(162, 170):
        g.on_quote(15, 209.0, 209.2, 209.5, now=t)
        fired += sum(1 for a in g.tick(now=t) if a[0] == "emergency")
    assert fired == 2, fired
    print("4. в DRY_RUN / режиме алерта — одно сообщение на пробой, а не каждые 5 с ✓")


def test_no_blind_market_close_without_price():
    g, ex, sent = make()
    g.on_positions({15: -3.0}, now=0)
    ex.book = 0.0                                        # котировок нет, стакан пуст
    run(g.run_actions([("emergency", 15, "тест", "failed_stop")]))
    assert ex.closes == [] and any("нет цены" in m for m in sent), sent
    assert g.retry_after.get(15, 0) > time.time()        # и не долбим биржу каждые полсекунды
    print("5. нет цены в стакане — закрытие «по любой цене» не отправляется ✓")


def test_stale_quote_uses_fresh_book():
    g, ex, sent = make()
    g.on_positions({15: 2.0}, now=0)
    g.on_quote(15, 300.0, 300.1, 300.0, now=time.time() - 30)   # котировка 30 с назад
    ex.book = 250.0                                              # а в стакане уже 250
    run(g.emergency_close(15, "тест", "act"))
    assert ex.closes and ex.closes[0][3] == round(250.0 * 0.99, 4), ex.closes
    print("6. старая котировка не используется — допуск считается от свежего стакана ✓")


def test_failed_close_pauses_retries():
    g, ex, sent = make()
    g.on_positions({15: 2.0}, now=0)
    g.on_orders([sl(1, 210)], snapshot=True)
    ex.fill, ex.book = False, 209.0
    g.on_quote(15, 209.0, 209.1, 209.0, now=time.time())
    G.asyncio_sleep = asyncio.sleep
    run(g.emergency_close(15, "тест", "act"))
    assert "НЕ удалось" in sent[-1] and g.retry_after[15] > time.time() + 50
    now = time.time()
    g.on_quote(15, 209.0, 209.1, 209.0, now=now)
    assert g.tick(now=now) == [] and g.tick(now=now + 6) == []   # пауза: не повторяем сразу
    print("7. после неудачного закрытия — пауза, а не бесконечные попытки каждые 5 с ✓")


def test_vanished_stop_beyond_trigger():
    g, ex, sent = make()
    g.on_positions({15: 2.0}, now=0)
    g.on_orders([sl(1, 210)], snapshot=True)
    now = time.time()
    g.on_quote(15, 205.0, 205.2, 205.1, now=now)               # mark уже ниже стопа 210
    acts = g.on_orders([], snapshot=True, now=now)             # после переподключения стопа нет
    assert [a[0] for a in acts] == ["emergency"] and "пропал" in acts[0][2], acts
    # mark ещё выше стопа — стоп просто сняли руками: ничего не делаем
    g2, *_ = make()
    g2.on_positions({15: 2.0}, now=0)
    g2.on_orders([sl(1, 210)], snapshot=True)
    g2.on_quote(15, 215.0, 215.2, 215.1, now=now)
    assert g2.on_orders([], snapshot=True, now=now) == []
    # стоп переставили (старый пропал, новый есть) — тоже ничего
    g3, *_ = make()
    g3.on_positions({15: 2.0}, now=0)
    g3.on_orders([sl(1, 210)], snapshot=True)
    g3.on_quote(15, 205.0, 205.2, 205.1, now=now)
    assert g3.on_orders([sl(2, 200)], snapshot=True, now=now) == []
    print("8. стоп пропал при переподключении, а mark за триггером — страж закрывает позицию ✓")


def test_rest_orders_sync_removes_phantom():
    g, ex, sent = make()
    g.on_positions({15: 2.0}, now=0)
    g.on_orders([sl(1, 210)], snapshot=True)
    now = time.time()
    g.on_quote(15, 215.0, 215.1, 215.0, now=now)
    assert g.sync_orders(15, [], now=now) == [] and not g.stops_for(15, 2.0)   # «призрак» убран
    g.on_orders([sl(5, 205)], now=now)                                    # свежее событие по WebSocket
    assert g.sync_orders(15, [], now=now + 1) == [] and g.stops_for(15, 2.0)  # REST его не затирает
    print("9. сверка ордеров по REST убирает «призраков», но не затирает свежие события ✓")


def test_rest_closure_needs_confirmation():
    class Http:
        def __init__(self, answers):
            self.answers = answers

    ex = G.LighterExchange(None, "robinhood", 7, 4, "0x00")
    answers = [({15: 0.0}, {15: 0}), ({15: 2.0}, {15: 1})]       # 1-й ответ — сбой, 2-й — позиция есть

    async def fetch():
        return answers.pop(0)
    ex._fetch_positions = fetch
    g = G.Guardian(ex, G.Config(), lambda t: None)
    ex.guardian = g
    g.on_positions({15: 2.0}, snapshot=True, now=0)
    orig = asyncio.sleep

    async def fast(s):
        await orig(0)
    G.asyncio.sleep = fast
    try:
        run(ex.refresh_positions())
    finally:
        G.asyncio.sleep = orig
    assert g.positions[15] == 2.0 and 15 not in g.pending_cleanup, (g.positions, g.pending_cleanup)
    print("10. разовый сбой REST не выглядит как закрытие позиции (нужно подтверждение) ✓")


def test_split_message_and_html_fallback():
    long = "\n".join(f"<b>строка {i}</b> " + "x" * 80 for i in range(120))
    parts = G.split_message(long)
    assert len(parts) > 1 and all(len(p) <= 3900 for p in parts)
    assert all(p.count("<b>") == p.count("</b>") for p in parts)      # теги не разорваны
    tg = G.Telegram(None, "token", "777")
    calls = []

    async def call(method, **p):
        calls.append(p)
        return {"ok": False, "description": "can't parse entities"} if p.get("parse_mode") else {"ok": True}
    tg.call = call
    run(tg.send("🛡 <b>#1 Основной & Ко RH</b>: тест"))
    assert len(calls) == 2 and "parse_mode" not in calls[1] and "<b>" not in calls[1]["text"]
    print("11. длинные сообщения режутся по строкам, при ошибке HTML уходит простым текстом ✓")


def test_label_escaped():
    g, ex, sent = make()
    assert "&amp;" in g.sym(15) and "& Ко" not in g.sym(15)
    print("12. имя кошелька экранируется — «&» и «<» не ломают сообщения ✓")


def test_telegram_conflict_warns_and_backs_off():
    tg = G.Telegram(None, "token", "777")
    sent, sleeps, n = [], [], {"i": 0}

    async def send(t):
        sent.append(t)
    tg.send = send

    async def call(method, **p):
        if p.get("offset") == -1:
            return {"ok": True, "result": []}
        n["i"] += 1
        if n["i"] > 3:
            raise asyncio.CancelledError
        return {"ok": False, "error_code": 409, "description": "Conflict"}
    tg.call = call
    orig = asyncio.sleep

    async def fake_sleep(s):
        sleeps.append(s)
    G.asyncio.sleep = fake_sleep
    try:
        run(tg.poll([], []))
    except asyncio.CancelledError:
        pass
    finally:
        G.asyncio.sleep = orig
    assert len(sent) == 1 and "отдельного бота" in sent[0] and sleeps and min(sleeps) >= 15, (sent, sleeps)
    print("13. бот занят другой программой — одно предупреждение и пауза, без бесконечного цикла ✓")


def test_ws_subscription_error_flag():
    ex = G.LighterExchange(None, "robinhood", 7, 4, "0x00")
    ex.guardian = G.Guardian(ex, G.Config(), lambda t: None)
    run(ex.on_ws({"error": {"code": 20013, "message": "invalid auth: expired token: account_all_orders:7"}}))
    assert "account_all_orders" in ex.sub_error
    run(ex.on_ws({"type": "subscribed/account_all_orders", "orders": {}}))
    assert ex.sub_error == ""
    print("14. отказ в подписке на ордера замечается (и сбрасывается после успешной подписки) ✓")


def test_market_close_never_with_zero_price():
    ex = G.LighterExchange(None, "robinhood", 7, 4, "0x00")
    ex.markets = {15: G.Market(15, "NVDA", 4, 2)}
    ok, err = run(ex.market_close(15, 1.0, True, 0.0))
    assert not ok and "цены" in err
    print("15. заявка с нулевой ценой не формируется ✓")


def test_start_retry_keeps_key():
    import lighter_signer as LS
    if not LS.signer_file()[0].exists():
        print("16. (пропуск: нет модуля подписи)")
        return
    priv, _ = LS.generate_api_key()
    ex = G.LighterExchange(None, "robinhood", 7, 4, priv)
    tries = {"n": 0}

    async def load():
        ex.markets = {15: G.Market(15, "NVDA", 4, 2)}

    async def verify():
        tries["n"] += 1
        if tries["n"] == 1:
            raise RuntimeError("сеть недоступна")
    ex.load_markets, ex.verify_key = load, verify
    try:
        run(ex.start())
    except RuntimeError:
        pass
    signer = ex.signer
    run(ex.start())                                   # повтор после сбоя
    assert ex.signer is signer and ex._api_private_key is None and tries["n"] == 2
    print("16. повторный запуск после сбоя сети не теряет ключ ✓")


def test_runner_one_wallet_down_others_work():
    class FakeEx:
        def __init__(self, label, wallet, fail_times):
            self.label, self.wallet, self.fail = label, wallet, fail_times
            self.venue, self.wallet_name, self.account_index = label.split()[-1], "", 1
            self.markets, self.guardian, self.last_msg, self.sub_error = {}, None, time.time(), ""

        async def start(self):
            if self.fail > 0:
                self.fail -= 1
                raise RuntimeError("биржа недоступна")

        async def refresh_positions(self):
            pass

        async def stream(self):
            await asyncio.sleep(3600)

    async def scenario():
        sent = []

        async def send(t):
            sent.append(G.strip_marks(t))
        tg = types.SimpleNamespace(send=send)
        cfg = G.Config()
        r = G.Runner(tg, cfg)
        orig = asyncio.sleep

        async def fast(s):
            await orig(0 if s >= 1 else s)
        G.asyncio.sleep = fast
        try:
            a, b = FakeEx("#1 RH", 1, 0), FakeEx("#1 CORE", 1, 2)
            await asyncio.wait([asyncio.create_task(r.start_exchange(1, a)),
                                asyncio.create_task(r.start_exchange(1, b))], timeout=2)
        finally:
            G.asyncio.sleep = orig
        for t in list(r.tasks):
            t.cancel()
        return r, sent

    r, sent = run(scenario())
    assert len(r.guardians) == 2 and len(r.hedges) == 1, (len(r.guardians), len(r.hedges))
    assert any("не удалось подключиться" in m for m in sent) and any("подключился" in m for m in sent)
    print("17. одна биржа не поднялась — остальные работают, упавшая переподключается сама ✓")


def test_hedge_no_price_no_blind_close():
    sent = []

    async def notify(t):
        sent.append(G.strip_marks(t))
    cfg = G.Config()
    cfg.dry_run, cfg.hedge, cfg.hedge_debounce = False, "act", 0
    exs = {}
    gs = {}
    for label, mid in (("RH", 15), ("CORE", 115)):
        e = Ex()
        e.label = label
        e.markets = {mid: G.Market(mid, "NVDA", 4, 2)}
        g = G.Guardian(e, cfg, notify)
        e.g = g
        g.on_positions({}, snapshot=True, now=0)
        exs[label], gs[label] = e, g
    hm = HG.HedgeManager(gs, cfg, notify)
    gs["RH"].on_positions({15: 1.0}, now=1)
    gs["CORE"].on_positions({115: -1.0}, now=1)
    hm.tick(now=2)
    gs["RH"].on_positions({15: 0.0}, now=3)
    acts = hm.tick(now=4)
    run(hm.run_actions(acts))
    assert exs["CORE"].closes == [] and any("нет цены" in m for m in sent), sent
    print("18. вилка: без цены в стакане вторую ногу «вслепую» не закрываем, а просим сделать вручную ✓")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
    print("\nВСЕ ТЕСТЫ ПРОВЕРКИ ПРОЙДЕНЫ")
