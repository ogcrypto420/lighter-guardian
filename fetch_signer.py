#!/usr/bin/env python3
"""
Скачивает официальный модуль подписи Lighter из репозитория elliottech/lighter-python
(зафиксированный коммит) и проверяет SHA-256. Без сторонних библиотек.

    python fetch_signer.py          # модуль для этого компьютера
    python fetch_signer.py --all    # для всех платформ (например, для сборки Docker)
"""
import argparse
import os
import sys
import tempfile
import urllib.error
import urllib.request

from lighter_signer import SIGNER_COMMIT, SIGNER_DIR, SIGNER_FILES, platform_key, sha256_file

BASE = f"https://raw.githubusercontent.com/elliottech/lighter-python/{SIGNER_COMMIT}/lighter/signers/"


def fetch(name: str, sha: str) -> None:
    dest = SIGNER_DIR / name
    if dest.exists():
        if sha256_file(dest) == sha:
            print(f"✓ {name} уже на месте, SHA-256 совпадает")
            return
        print(f"⚠️ {name} на месте, но SHA-256 не совпадает — скачиваю заново")
    SIGNER_DIR.mkdir(parents=True, exist_ok=True)
    print(f"↓ {name} …")
    fd, tmp = tempfile.mkstemp(dir=SIGNER_DIR, prefix=".dl-")
    try:
        try:
            with os.fdopen(fd, "wb") as f, urllib.request.urlopen(BASE + name, timeout=120) as r:
                while chunk := r.read(1 << 20):
                    f.write(chunk)
        except (urllib.error.URLError, OSError) as e:
            raise SystemExit(
                f"❌ Не удалось скачать {name}: {getattr(e, 'reason', e)}\n"
                f"Можно скачать вручную: https://github.com/elliottech/lighter-python/blob/{SIGNER_COMMIT}"
                f"/lighter/signers/{name}\n"
                f"Положи файл в папку {SIGNER_DIR} и запусти python fetch_signer.py ещё раз: он проверит SHA-256."
            ) from None
        actual = sha256_file(tmp)
        if actual != sha:
            raise SystemExit(f"❌ {name}: SHA-256 не совпадает ({actual}), файл не сохранён.")
        os.replace(tmp, dest)
        print(f"✓ {name}: SHA-256 совпадает")
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="скачать модули для всех платформ")
    args = ap.parse_args()
    items = SIGNER_FILES.values() if args.all else [SIGNER_FILES.get(platform_key())]
    if None in items:
        sys.exit(f"Платформа {platform_key()} не поддерживается модулем подписи Lighter")
    for name, sha in items:
        fetch(name, sha)


if __name__ == "__main__":
    main()
