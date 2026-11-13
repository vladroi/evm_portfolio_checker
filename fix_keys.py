#!/usr/bin/env python3
"""Safely rebuild local EVM keystores from owned plaintext keys using one new password.

Only local file operations; does not connect to networks, sign, or broadcast transactions.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
from getpass import getpass
from pathlib import Path

from eth_account import Account

BASE = Path(__file__).resolve().parent
INPUT = BASE / 'private_keys.txt'
ALLOW = BASE / 'addresses.txt'
VAULT = BASE / 'local_vault'
WORK = BASE / '.vault_work'


def fail(msg: str):
    raise RuntimeError(msg)


def protect_git():
    """Check that sensitive existing files are not Git-tracked and make new files ignored."""
    if not shutil.which('git'):
        return
    probe = subprocess.run(['git', 'rev-parse', '--show-toplevel'], cwd=BASE,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if probe.returncode != 0:
        return
    for path in (INPUT, VAULT):
        out = subprocess.run(['git','ls-files','--', str(path.relative_to(BASE))], cwd=BASE,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if out.returncode == 0 and out.stdout.strip():
            fail(f'Секретные файлы уже отслеживаются Git: {path.name}. '
                 'Остановлено. Нужно удалить их из истории Git и заменить скомпрометированные ключи.')
    ignore = BASE / '.gitignore'
    existing = ignore.read_text(encoding='utf-8') if ignore.exists() else ''
    required = ['/private_keys.txt', '/local_vault/', '/.vault_work/']
    missing = [line for line in required if line not in existing.splitlines()]
    if missing:
        with ignore.open('a', encoding='utf-8') as f:
            f.write(('\n' if existing and not existing.endswith('\n') else '') +
                    '# Local keys and vault backups — NEVER commit\n' + '\n'.join(missing) + '\n')
    for rel in ('private_keys.txt', 'local_vault/', '.vault_work/'):
        check = subprocess.run(['git', 'check-ignore', '-q', rel], cwd=BASE,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check.returncode != 0:
            fail(f'Не удалось исключить {rel} из Git. Импорт остановлен.')


def parse_inputs():
    if not INPUT.is_file() or INPUT.is_symlink():
        fail('Не найден обычный private_keys.txt рядом с fix_keys.py. '
             'Нужны исходные приватные ключи или старый пароль; без них хранилище не восстановить.')
    if not ALLOW.is_file():
        fail('Не найден addresses.txt рядом с fix_keys.py.')
    allowed = {line.strip().lower() for line in ALLOW.read_text(encoding='utf-8-sig').splitlines()
               if line.strip().lower().startswith('0x') and len(line.strip()) == 42}
    if not allowed:
        fail('В addresses.txt нет адресов для сверки.')
    # Never print user keys, even for malformed lines.
    keys = {}
    invalid = 0
    unlisted = 0
    for raw in INPUT.read_text(encoding='utf-8-sig').splitlines():
        value = raw.strip()
        if not value or value.startswith('#') or value.startswith('//'):
            continue
        try:
            account = Account.from_key(value)
        except Exception:
            invalid += 1
            continue
        addr = account.address.lower()
        if addr not in allowed:
            unlisted += 1
            continue
        if addr in keys and keys[addr] != value:
            fail('Обнаружены конфликтующие ключи одного адреса. Ничего не изменено.')
        keys[addr] = value
    if not keys:
        fail('Нет подходящих приватных ключей в private_keys.txt.')
    if invalid:
        fail(f'Невалидных строк ключей: {invalid}. Исправь файл; хранилище не менялось.')
    if VAULT.exists() and VAULT.is_symlink():
        fail('local_vault — символическая ссылка. Отменено.')
    existing = {p.stem.lower() for p in VAULT.glob('*.json')} if VAULT.is_dir() else set()
    missing = existing - keys.keys()
    if missing:
        fail(f'В старом хранилище {len(existing)} ключей, а в private_keys.txt '
             f'не хватает {len(missing)} из них. Не стану терять эти ключи. '
             'Добавь исходные ключи всех существующих адресов в private_keys.txt.')
    return keys, unlisted, existing


def main():
    protect_git()
    keys, unlisted, existing = parse_inputs()
    if os.name == 'posix':
        os.chmod(INPUT, 0o600)
    print(f'Найдено {len(keys)} подходящих ключей. Старых keystore: {len(existing)}.')
    if unlisted:
        print(f'Дополнительно пропущено ключей вне addresses.txt: {unlisted}.')
    print('Переводы не запускаются. Хранилище будет заменено только после проверки всех новых keystore.')
    password = getpass('Придумай НОВЫЙ пароль хранилища (12+ символов): ')
    repeat = getpass('Повтори новый пароль: ')
    if password != repeat or len(password) < 12:
        fail('Пароли не совпадают или длина меньше 12 символов. Ничего не изменено.')

    WORK.mkdir(mode=0o700, exist_ok=True)
    if os.name == 'posix':
        os.chmod(WORK, 0o700)
    nonce = secrets.token_hex(8)
    staging = WORK / ('new_' + nonce)
    staging.mkdir(mode=0o700)
    swapped = False
    backup = None
    try:
        for address, key in keys.items():
            doc = Account.encrypt(key, password)
            dest = staging / (address + '.json')
            with os.fdopen(os.open(dest, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600), 'w') as f:
                json.dump(doc, f)
            # Verify that same password can decrypt each new keystore and recover the right address.
            verified = Account.from_key(Account.decrypt(doc, password)).address.lower()
            if verified != address:
                fail('Внутренняя проверка зашифрованных ключей не пройдена.')
        print(f'Успешно проверено зашифрованных ключей: {len(keys)}.')
        if VAULT.exists():
            backup = WORK / ('old_' + nonce)
            VAULT.rename(backup)
        try:
            staging.rename(VAULT)
            swapped = True
        except Exception:
            if backup and backup.exists() and not VAULT.exists():
                backup.rename(VAULT)
            raise
    finally:
        if not swapped and staging.exists():
            shutil.rmtree(staging)
    print('ГОТОВО. Новый local_vault создан и проверен. Старые ключи не перезаписывались.')
    if backup:
        print('Резервная копия старого хранилища: ' + str(backup.relative_to(BASE)))
    print('Теперь запусти: python start.py')
    print('Не отправляй private_keys.txt в чат или Git. После импорта убери его в офлайн-хранилище.')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, json.JSONDecodeError) as exc:
        print('ОСТАНОВКА:', exc, file=sys.stderr)
        sys.exit(1)
