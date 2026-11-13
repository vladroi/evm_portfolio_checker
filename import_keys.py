#!/usr/bin/env python3
"""Offline import of locally controlled keys into individual password-encrypted JSON keystores.

Never send keys anywhere, print them, or write them into scanner reports.
"""
import argparse
import json
import os
import subprocess
import shutil
from getpass import getpass
from pathlib import Path
from eth_account import Account


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', default='private_keys.txt', help='LOCAL input file, default private_keys.txt')
    p.add_argument('--addresses',default='addresses.txt',help='Public addresses allowed to import')
    p.add_argument('--vault',default='local_vault')
    args=p.parse_args()
    src=Path(args.input)
    if not src.is_file():
        p.error('Input keys file does not exist')
    if src.is_symlink():
        p.error('Refusing symlinked private key file')
    # Refuse already-tracked secrets, and automatically add an exclusion before
    # reading the input. Ignore only the actual key path and the local vault.
    if shutil.which('git'):
        top = subprocess.run(['git','rev-parse','--show-toplevel'], cwd=src.parent,
                             capture_output=True, text=True, check=False)
        if top.returncode == 0:
            root = Path(top.stdout.strip()).resolve()
            try:
                rel = src.resolve().relative_to(root).as_posix()
            except ValueError:
                rel = None
            if rel:
                tracked = subprocess.run(['git','ls-files','--error-unmatch','--',rel],
                    cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                if tracked.returncode == 0:
                    p.error('Key file is already tracked by Git. Remove from Git history and rotate exposed keys.')
                gi = root / '.gitignore'
                current = gi.read_text(encoding='utf-8') if gi.exists() else ''
                patterns = ('/' + rel, '/local_vault/', '/consolidation/')
                missing = [pattern for pattern in patterns if pattern not in current.splitlines()]
                if missing:
                    with gi.open('a', encoding='utf-8') as out:
                        out.write(('\n' if current and not current.endswith('\n') else '') +
                            '\n# Local crypto secrets and transaction state\n' + '\n'.join(missing) + '\n')
                ignored = subprocess.run(['git','check-ignore','--quiet','--',rel], cwd=root,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                if ignored.returncode != 0:
                    p.error('Cannot guarantee Git ignores the key file; stopping.')
    # Auto-correct permissions rather than asking the user to run chmod manually.
    if os.name == 'posix':
        os.chmod(src, 0o600)
        if src.stat().st_mode & 0o077:
            p.error('Could not protect key file permissions')
    allowed={line.strip().lower() for line in Path(args.addresses).read_text().splitlines()
             if line.strip().startswith('0x') and len(line.strip())==42}
    if not allowed:
        p.error('addresses.txt contains no source addresses')
    vault=Path(args.vault)
    vault.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(vault,0o700)
    pw=getpass('New password for encrypted key vault: ')
    confirm=getpass('Repeat password: ')
    if pw!=confirm or len(pw)<12:
        p.error('Passwords do not match or shorter than 12 characters')
    imported=0
    rejected=0
    try:
        with src.open(encoding='utf-8-sig') as fh:
            for row in fh:
                key=row.strip()
                if not key or key.startswith('#'):
                    continue
                try:
                    account=Account.from_key(key)
                except Exception:
                    rejected+=1
                    continue
                if account.address.lower() not in allowed:
                    rejected+=1
                    continue
                dest=vault/(account.address.lower()+'.json')
                if dest.exists():
                    continue
                ciphertext=Account.encrypt(key,pw)
                flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
                fd=os.open(dest,flags,0o600)
                with os.fdopen(fd,'w') as out:
                    json.dump(ciphertext,out)
                imported+=1
    finally:
        # Does not securely wipe original plaintext from SSD snapshots/backups.
        pw='';confirm=''
    print(f'Imported {imported} encrypted keystores. Rejected {rejected} unrelated/invalid lines.')
    print('Keep the original keys offline; do not add the original input file or local_vault to Git.')

if __name__=='__main__':
    main()
