# Railgun Kohaku C Derivation

This repository contains a small C library that derives a RAILGUN Kohaku-style account directly from a BIP-39 mnemonic.

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

## API

The public header is [include/railgun_kohaku.h](/tmp/codex-run-e36mzeak/working/include/railgun_kohaku.h:1).

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

## Test coverage

The test binary in [tests/test_railgun_kohaku.c](/tmp/codex-run-e36mzeak/working/tests/test_railgun_kohaku.c:1) covers:

- The standard BIP-39 seed vector for `"abandon ... about"`.
- A deterministic account-generation vector from that mnemonic.

## Scope

This implementation is intended for direct mnemonic-to-account derivation and address encoding. It does not implement note encryption, transaction proving, or the broader RAILGUN wallet engine.
