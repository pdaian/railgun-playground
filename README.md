# Railgun Kohaku Derivation

This repository contains a small C library and a matching Python module that derive a RAILGUN Kohaku-style account directly from a BIP-39 mnemonic.

It also includes a minimal in-memory ledger layer for local account primitives:

- Check account balance and active/inactive status.
- Receive funds into an address.
- Send funds between derived addresses.

It is self-contained at the protocol layer:

- BIP-39 seed derivation via PBKDF2-HMAC-SHA512.
- Hardened BIP-32 derivation for the spending path `m/44'/1984'/0'/0'/index'`.
- Hardened BIP-32 derivation for the viewing path `m/420'/1984'/0'/0'/index'`.
- BabyJub spending public key derivation using the circomlib-compatible `prv2pub` flow:
  `BLAKE-512 -> prune -> little-endian scalar -> >> 3 -> Base8 scalar multiply`.
- Ed25519 viewing public key derivation from the 32-byte viewing private key.
- Poseidon over BN254 for the nullifying key and master public key.
- `0zk` bech32m address encoding.

## Dependency model

The code is standalone except for `libcrypto` from OpenSSL, which is used for:

- PBKDF2 / HMAC / SHA-512 primitives.
- Ed25519 raw key handling.
- `BIGNUM` arithmetic over BN254.

There are no TypeScript dependencies, generated files, or code-generation steps.

## Python API

The Python implementation lives in [railgun_kohaku.py](/tmp/codex-run-mcqxwsis/working/railgun_kohaku.py:1).

Primary entrypoints:

```python
from railgun_kohaku import account_from_mnemonic, seed_from_mnemonic
from railgun_kohaku import RailgunKohakuLedger

seed = seed_from_mnemonic(mnemonic, passphrase="")
account = account_from_mnemonic(
    mnemonic,
    passphrase="",
    index=0,
    use_chain=True,
    chain_type=0,
    chain_id=1,
)
ledger = RailgunKohakuLedger()
ledger.receive_funds(account, 100)
balance = ledger.check_account_balance(account.address)
```

`account_from_mnemonic(...)` returns a frozen dataclass with:

- 32-byte spending, viewing, and viewing-public keys as `bytes`.
- Decimal string fields for the BabyJub public coordinates, nullifying key, and master public key.
- The final bech32m `0zk` address string.

`RailgunKohakuLedger` provides:

- `set_balance(address, balance)`
- `check_account_balance(address)`
- `send_funds(from_account_or_address, to_account_or_address, amount)`
- `receive_funds(to_account_or_address, amount, source_address="external")`

## C API

The public header is [include/railgun_kohaku.h](/tmp/codex-run-mcqxwsis/working/include/railgun_kohaku.h:1).

Primary entrypoint:

```c
int railgun_kohaku_account_from_mnemonic(
  const char *mnemonic,
  const char *passphrase,
  uint32_t index,
  int use_chain,
  uint8_t chain_type,
  uint64_t chain_id,
  railgun_kohaku_account_t *out,
  char error[RAILGUN_ERROR_BUF]
);
```

Additional in-memory ledger primitives:

```c
railgun_kohaku_ledger_entry_t entries[8];
railgun_kohaku_ledger_t ledger;
railgun_kohaku_balance_info_t balance;
railgun_kohaku_transfer_receipt_t receipt;
char error[RAILGUN_ERROR_BUF];

railgun_kohaku_ledger_init(&ledger, entries, 8, error);
railgun_kohaku_receive_funds(&ledger, account.address, 100, NULL, &receipt, error);
railgun_kohaku_check_account_balance(&ledger, account.address, &balance, error);
```

Notes:

- `passphrase` is the standard BIP-39 passphrase. Pass `""` for none.
- `index` is the RAILGUN wallet index appended to both hardened derivation paths.
- `use_chain = 0` emits an all-chains address.
- `use_chain = 1` encodes a chain-specific address. The test vector uses `chain_type = 0` and `chain_id = 1` for Ethereum mainnet.

## Build

```sh
make
make test
```

## Python Tests

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_railgun_kohaku
```

## Test coverage

The C and Python tests in [tests/test_railgun_kohaku.c](/tmp/codex-run-mcqxwsis/working/tests/test_railgun_kohaku.c:1) and [tests/test_railgun_kohaku.py](/tmp/codex-run-mcqxwsis/working/tests/test_railgun_kohaku.py:1) cover:

- The standard BIP-39 seed vector for `"abandon ... about"`.
- A deterministic account-generation vector from that mnemonic.

## Scope

This implementation is intended for direct mnemonic-to-account derivation and address encoding. It does not implement note encryption, transaction proving, or the broader RAILGUN wallet engine.
