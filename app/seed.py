"""Seeder: identitas provider (attacker/victim/evilclone) + flag victim + setting bawaan."""
from .models import seed as _seed


def main():
    _seed()
    print('Seed OK: attacker@evil.com, victim@corp.test (FLAG), evilclone (email victim, unverified)')


if __name__ == '__main__':
    main()