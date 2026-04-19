"""Python implementation of the RAILGUN Kohaku account derivation flow."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Sequence
import unicodedata


_MASK_64 = (1 << 64) - 1
_SECP256K1_ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
_BN254_FIELD = int(
    "30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001", 16
)
_BLAKE512_IV = (
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
)
_BLAKE512_SIGMA = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
)
_BLAKE512_C = (
    0x243F6A8885A308D3,
    0x13198A2E03707344,
    0xA4093822299F31D0,
    0x082EFA98EC4E6C89,
    0x452821E638D01377,
    0xBE5466CF34E90C6C,
    0xC0AC29B7C97C50DD,
    0x3F84D5B5B5470917,
    0x9216D5D98979FB1B,
    0xD1310BA698DFB5AC,
    0x2FFD72DBD01ADFB7,
    0xB8E1AFED6A267E96,
    0xBA7C9045F12C7F99,
    0x24A19947B3916CF7,
    0x0801F2E2858EFC16,
    0x636920D871574E69,
)
_BABYJUB_A = int("168700", 16)
_BABYJUB_D = int("168696", 16)
_BABYJUB_BASE8 = (
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203,
)
_POSEIDON_PARTIAL_ROUNDS = (56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65)
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_ED25519_P = 2**255 - 19
_ED25519_D = -121665 * pow(121666, -1, _ED25519_P) % _ED25519_P
_ED25519_I = pow(2, (_ED25519_P - 1) // 4, _ED25519_P)
_ED25519_BASE = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)
_SPENDING_PATH_PREFIX = (44, 1984, 0, 0)
_VIEWING_PATH_PREFIX = (420, 1984, 0, 0)


@dataclass(frozen=True, slots=True)
class RailgunKohakuAccount:
    spending_private_key: bytes
    viewing_private_key: bytes
    viewing_public_key: bytes
    spending_public_key_x: str
    spending_public_key_y: str
    nullifying_key: str
    master_public_key: str
    address: str


@dataclass(frozen=True, slots=True)
class RailgunKohakuBalanceInfo:
    balance: int
    is_active: bool
    status: str


@dataclass(frozen=True, slots=True)
class RailgunKohakuTransferReceipt:
    tx_id: str
    from_address: str
    to_address: str
    amount: int
    sender_balance: int
    recipient_balance: int


class RailgunKohakuLedger:
    """In-memory account balance primitives for local send/receive flows."""

    __slots__ = ("_balances",)

    def __init__(self) -> None:
        self._balances: dict[str, int] = {}

    def set_balance(self, address: str, balance: int) -> None:
        _validate_address(address)
        _validate_balance(balance)
        self._balances[address] = balance

    def check_account_balance(self, address: str) -> RailgunKohakuBalanceInfo:
        _validate_address(address)
        balance = self._balances.get(address, 0)
        is_active = balance > 0
        return RailgunKohakuBalanceInfo(
            balance=balance,
            is_active=is_active,
            status="active" if is_active else "inactive",
        )

    def send_funds(
        self,
        from_account: RailgunKohakuAccount | str,
        to_account: RailgunKohakuAccount | str,
        amount: int,
    ) -> RailgunKohakuTransferReceipt:
        from_address = _account_address(from_account)
        to_address = _account_address(to_account)
        _validate_transfer(from_address, to_address, amount)

        sender_balance = self._balances.get(from_address, 0)
        if sender_balance < amount:
            raise ValueError("insufficient funds")

        recipient_balance = self._balances.get(to_address, 0)
        sender_balance -= amount
        recipient_balance += amount
        self._balances[from_address] = sender_balance
        self._balances[to_address] = recipient_balance
        return _build_receipt(
            from_address,
            to_address,
            amount,
            sender_balance,
            recipient_balance,
        )

    def receive_funds(
        self,
        to_account: RailgunKohakuAccount | str,
        amount: int,
        source_address: str = "external",
    ) -> RailgunKohakuTransferReceipt:
        to_address = _account_address(to_account)
        _validate_address(to_address)
        _validate_amount(amount)
        if not source_address:
            source_address = "external"
        _validate_address(source_address)
        if source_address == to_address:
            raise ValueError("source and destination addresses must differ")

        recipient_balance = self._balances.get(to_address, 0) + amount
        self._balances[to_address] = recipient_balance
        return _build_receipt(source_address, to_address, amount, 0, recipient_balance)


def seed_from_mnemonic(mnemonic: str, passphrase: str = "") -> bytes:
    """Derive the 64-byte BIP-39 seed from a mnemonic and optional passphrase."""
    if not mnemonic:
        raise ValueError("mnemonic is required")
    normalized_mnemonic = unicodedata.normalize("NFKD", mnemonic)
    normalized_passphrase = unicodedata.normalize("NFKD", passphrase)
    salt = ("mnemonic" + normalized_passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac(
        "sha512",
        normalized_mnemonic.encode("utf-8"),
        salt,
        2048,
        dklen=64,
    )


def account_from_mnemonic(
    mnemonic: str,
    passphrase: str = "",
    index: int = 0,
    use_chain: bool = False,
    chain_type: int = 0,
    chain_id: int = 0,
) -> RailgunKohakuAccount:
    """Derive a RAILGUN Kohaku account from a BIP-39 mnemonic."""
    if index < 0:
        raise ValueError("index must be non-negative")
    if not 0 <= chain_type <= 0xFF:
        raise ValueError("chain_type must fit in one byte")
    if not 0 <= chain_id < 1 << 56:
        raise ValueError("chain_id must fit in seven bytes")

    seed = seed_from_mnemonic(mnemonic, passphrase)
    spending_private_key, _ = _derive_path_hardened(seed, (*_SPENDING_PATH_PREFIX, index))
    viewing_private_key, _ = _derive_path_ed25519_hardened(
        seed, (*_VIEWING_PATH_PREFIX, index)
    )
    viewing_public_key = _ed25519_public_from_seed(viewing_private_key)
    spending_public_key_x, spending_public_key_y = _derive_spending_public_key(
        spending_private_key
    )
    nullifying_key = _poseidon_hash([int.from_bytes(viewing_private_key, "big")])
    master_public_key = _poseidon_hash(
        [spending_public_key_x, spending_public_key_y, nullifying_key]
    )
    address = _encode_address(
        spending_public_key_x,
        spending_public_key_y,
        viewing_public_key,
        use_chain=use_chain,
        chain_type=chain_type,
        chain_id=chain_id,
    )
    return RailgunKohakuAccount(
        spending_private_key=spending_private_key,
        viewing_private_key=viewing_private_key,
        viewing_public_key=viewing_public_key,
        spending_public_key_x=str(spending_public_key_x),
        spending_public_key_y=str(spending_public_key_y),
        nullifying_key=str(nullifying_key),
        master_public_key=str(master_public_key),
        address=address,
    )


def _account_address(value: RailgunKohakuAccount | str) -> str:
    return value.address if isinstance(value, RailgunKohakuAccount) else value


def _validate_address(address: str) -> None:
    if not address:
        raise ValueError("address is required")


def _validate_amount(amount: int) -> None:
    if amount <= 0:
        raise ValueError("amount must be greater than zero")


def _validate_balance(balance: int) -> None:
    if balance < 0:
        raise ValueError("balance must be non-negative")


def _validate_transfer(from_address: str, to_address: str, amount: int) -> None:
    _validate_address(from_address)
    _validate_address(to_address)
    if from_address == to_address:
        raise ValueError("from and to addresses must differ")
    _validate_amount(amount)


def _build_receipt(
    from_address: str,
    to_address: str,
    amount: int,
    sender_balance: int,
    recipient_balance: int,
) -> RailgunKohakuTransferReceipt:
    tx_id = hashlib.sha256(
        f"{from_address}|{to_address}|{amount}|{sender_balance}|{recipient_balance}".encode(
            "utf-8"
        )
    ).hexdigest()
    return RailgunKohakuTransferReceipt(
        tx_id=tx_id,
        from_address=from_address,
        to_address=to_address,
        amount=amount,
        sender_balance=sender_balance,
        recipient_balance=recipient_balance,
    )


def _rotr64(value: int, count: int) -> int:
    return ((value >> count) | (value << (64 - count))) & _MASK_64


def _blake512_g(
    state: list[int],
    a: int,
    b: int,
    c: int,
    d: int,
    mx: int,
    my: int,
    cx: int,
    cy: int,
) -> None:
    state[a] = (state[a] + state[b] + (mx ^ cy)) & _MASK_64
    state[d] = _rotr64(state[d] ^ state[a], 32)
    state[c] = (state[c] + state[d]) & _MASK_64
    state[b] = _rotr64(state[b] ^ state[c], 25)
    state[a] = (state[a] + state[b] + (my ^ cx)) & _MASK_64
    state[d] = _rotr64(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK_64
    state[b] = _rotr64(state[b] ^ state[c], 11)


def _blake512_compress(h: list[int], t0: int, t1: int, block: bytes, last: bool) -> None:
    message = [int.from_bytes(block[offset : offset + 8], "big") for offset in range(0, 128, 8)]
    state = list(h) + [
        _BLAKE512_C[0],
        _BLAKE512_C[1],
        _BLAKE512_C[2],
        _BLAKE512_C[3],
        t0 ^ _BLAKE512_C[4],
        t0 ^ _BLAKE512_C[5],
        t1 ^ _BLAKE512_C[6],
        t1 ^ _BLAKE512_C[7],
    ]
    if last:
        state[14] = (~state[14]) & _MASK_64

    for sigma in _BLAKE512_SIGMA:
        _blake512_g(
            state, 0, 4, 8, 12, message[sigma[0]], message[sigma[1]], _BLAKE512_C[sigma[0]], _BLAKE512_C[sigma[1]]
        )
        _blake512_g(
            state, 1, 5, 9, 13, message[sigma[2]], message[sigma[3]], _BLAKE512_C[sigma[2]], _BLAKE512_C[sigma[3]]
        )
        _blake512_g(
            state, 2, 6, 10, 14, message[sigma[4]], message[sigma[5]], _BLAKE512_C[sigma[4]], _BLAKE512_C[sigma[5]]
        )
        _blake512_g(
            state, 3, 7, 11, 15, message[sigma[6]], message[sigma[7]], _BLAKE512_C[sigma[6]], _BLAKE512_C[sigma[7]]
        )
        _blake512_g(
            state, 0, 5, 10, 15, message[sigma[8]], message[sigma[9]], _BLAKE512_C[sigma[8]], _BLAKE512_C[sigma[9]]
        )
        _blake512_g(
            state, 1, 6, 11, 12, message[sigma[10]], message[sigma[11]], _BLAKE512_C[sigma[10]], _BLAKE512_C[sigma[11]]
        )
        _blake512_g(
            state, 2, 7, 8, 13, message[sigma[12]], message[sigma[13]], _BLAKE512_C[sigma[12]], _BLAKE512_C[sigma[13]]
        )
        _blake512_g(
            state, 3, 4, 9, 14, message[sigma[14]], message[sigma[15]], _BLAKE512_C[sigma[14]], _BLAKE512_C[sigma[15]]
        )

    for index in range(8):
        h[index] ^= state[index] ^ state[index + 8]


def _blake512(data: bytes) -> bytes:
    h = list(_BLAKE512_IV)
    t0 = 0
    t1 = 0
    offset = 0
    while offset + 128 <= len(data):
        t0 = (t0 + 1024) & _MASK_64
        if t0 < 1024:
            t1 = (t1 + 1) & _MASK_64
        _blake512_compress(h, t0, t1, data[offset : offset + 128], last=False)
        offset += 128

    tail = bytearray(data[offset:])
    bit_len_hi = t1
    bit_len_lo = (t0 + len(tail) * 8) & _MASK_64
    if bit_len_lo < t0:
        bit_len_hi = (bit_len_hi + 1) & _MASK_64

    block = bytearray(128)
    block[: len(tail)] = tail
    block[len(tail)] = 0x80
    if len(tail) > 111:
        _blake512_compress(h, t0, t1, bytes(block), last=False)
        block = bytearray(128)
    block[111] |= 0x01
    block[112:120] = bit_len_hi.to_bytes(8, "big")
    block[120:128] = bit_len_lo.to_bytes(8, "big")
    _blake512_compress(h, bit_len_lo, bit_len_hi, bytes(block), last=True)
    return b"".join(word.to_bytes(8, "big") for word in h)


def _hmac_sha512(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha512).digest()


def _child_key_derivation_hardened(
    parent_key: bytes, parent_chain_code: bytes, index: int
) -> tuple[bytes, bytes]:
    data = b"\x00" + parent_key + index.to_bytes(4, "big")
    digest = _hmac_sha512(parent_chain_code, data)
    child_int = (
        int.from_bytes(parent_key, "big") + int.from_bytes(digest[:32], "big")
    ) % _SECP256K1_ORDER
    return child_int.to_bytes(32, "big"), digest[32:]


def _child_key_derivation_ed25519_hardened(
    parent_key: bytes, parent_chain_code: bytes, index: int
) -> tuple[bytes, bytes]:
    data = b"\x00" + parent_key + index.to_bytes(4, "big")
    digest = _hmac_sha512(parent_chain_code, data)
    return digest[:32], digest[32:]


def _derive_path_hardened(seed: bytes, segments: Sequence[int]) -> tuple[bytes, bytes]:
    digest = _hmac_sha512(b"Bitcoin seed", seed)
    key = digest[:32]
    chain_code = digest[32:]
    for segment in segments:
        key, chain_code = _child_key_derivation_hardened(
            key, chain_code, 0x80000000 + segment
        )
    return key, chain_code


def _derive_path_ed25519_hardened(seed: bytes, segments: Sequence[int]) -> tuple[bytes, bytes]:
    digest = _hmac_sha512(b"ed25519 seed", seed)
    key = digest[:32]
    chain_code = digest[32:]
    for segment in segments:
        key, chain_code = _child_key_derivation_ed25519_hardened(
            key, chain_code, 0x80000000 + segment
        )
    return key, chain_code


def _babyjub_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    x1x2 = (x1 * x2) % _BN254_FIELD
    y1y2 = (y1 * y2) % _BN254_FIELD
    dxxyy = (_BABYJUB_D * x1x2 * y1y2) % _BN254_FIELD
    x_num = (x1 * y2 + y1 * x2) % _BN254_FIELD
    x_den = (1 + dxxyy) % _BN254_FIELD
    y_num = (y1y2 - _BABYJUB_A * x1x2) % _BN254_FIELD
    y_den = (1 - dxxyy) % _BN254_FIELD
    x3 = (x_num * pow(x_den, -1, _BN254_FIELD)) % _BN254_FIELD
    y3 = (y_num * pow(y_den, -1, _BN254_FIELD)) % _BN254_FIELD
    return x3, y3


def _babyjub_mul_base8(scalar: int) -> tuple[int, int]:
    acc = (0, 1)
    base = _BABYJUB_BASE8
    for bit_index in range(scalar.bit_length()):
        if scalar & (1 << bit_index):
            acc = _babyjub_add(acc, base)
        base = _babyjub_add(base, base)
    return acc


def _derive_spending_public_key(private_key: bytes) -> tuple[int, int]:
    pruned = bytearray(_blake512(private_key)[:32])
    pruned[0] &= 0xF8
    pruned[31] &= 0x7F
    pruned[31] |= 0x40
    scalar = int.from_bytes(bytes(reversed(pruned)), "big") >> 3
    return _babyjub_mul_base8(scalar)


def _grain_bit(state: list[int]) -> int:
    bit = state[0] ^ state[13] ^ state[23] ^ state[38] ^ state[51] ^ state[62]
    del state[0]
    state.append(bit & 1)
    return bit & 1


def _poseidon_round_constants(width: int, full_rounds: int, partial_rounds: int) -> list[int]:
    state = [0] * 80
    state[1] = 1
    state[5] = 1
    for index in range(12):
        state[6 + index] = (255 >> (11 - index)) & 1
        state[18 + index] = (width >> (11 - index)) & 1
    for index in range(10):
        state[30 + index] = (full_rounds >> (9 - index)) & 1
        state[40 + index] = (partial_rounds >> (9 - index)) & 1
    state[50:80] = [1] * 30
    for _ in range(160):
        _grain_bit(state)

    constants: list[int] = []
    total = (full_rounds + partial_rounds) * width
    while len(constants) < total:
        bits: list[int] = []
        while len(bits) < 255:
            bit1 = _grain_bit(state)
            bit2 = _grain_bit(state)
            if bit1:
                bits.append(bit2)
        packed = bytearray(32)
        for index, bit in enumerate(bits):
            if bit:
                packed[index // 8] |= 1 << (7 - (index % 8))
        candidate = int.from_bytes(packed, "big")
        if candidate < _BN254_FIELD:
            constants.append(candidate)
    return constants


def _poseidon_mds(width: int) -> list[list[int]]:
    return [
        [pow(row + width + column, -1, _BN254_FIELD) for column in range(width)]
        for row in range(width)
    ]


def _poseidon_hash(inputs: Sequence[int]) -> int:
    width = len(inputs) + 1
    if not 2 <= width <= 13:
        raise ValueError("Poseidon supports between 1 and 12 inputs")
    full_rounds = 8
    partial_rounds = _POSEIDON_PARTIAL_ROUNDS[width - 2]
    constants = _poseidon_round_constants(width, full_rounds, partial_rounds)
    mds = _poseidon_mds(width)
    state = [0, *[value % _BN254_FIELD for value in inputs]]
    rounds = full_rounds + partial_rounds

    for round_index in range(rounds):
        base = round_index * width
        for index in range(width):
            state[index] = (state[index] + constants[base + index]) % _BN254_FIELD
        full_sbox = round_index < full_rounds // 2 or round_index >= full_rounds // 2 + partial_rounds
        if full_sbox:
            state = [pow(value, 5, _BN254_FIELD) for value in state]
        else:
            state[0] = pow(state[0], 5, _BN254_FIELD)
        state = [
            sum((mds[row][column] * state[column]) % _BN254_FIELD for column in range(width))
            % _BN254_FIELD
            for row in range(width)
        ]
    return state[1]


def _ed25519_recover_x(y: int, sign: int) -> int:
    numerator = (y * y - 1) % _ED25519_P
    denominator = (_ED25519_D * y * y + 1) % _ED25519_P
    x = pow(numerator * pow(denominator, -1, _ED25519_P), (_ED25519_P + 3) // 8, _ED25519_P)
    if (x * x - numerator * pow(denominator, -1, _ED25519_P)) % _ED25519_P != 0:
        x = (x * _ED25519_I) % _ED25519_P
    if x & 1 != sign:
        x = (-x) % _ED25519_P
    return x


def _ed25519_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    x_num = (x1 * y2 + x2 * y1) % _ED25519_P
    x_den = (1 + _ED25519_D * x1 * x2 * y1 * y2) % _ED25519_P
    y_num = (y1 * y2 + x1 * x2) % _ED25519_P
    y_den = (1 - _ED25519_D * x1 * x2 * y1 * y2) % _ED25519_P
    x3 = (x_num * pow(x_den, -1, _ED25519_P)) % _ED25519_P
    y3 = (y_num * pow(y_den, -1, _ED25519_P)) % _ED25519_P
    return x3, y3


def _ed25519_scalar_mult(scalar: int, point: tuple[int, int]) -> tuple[int, int]:
    result = (0, 1)
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed25519_add(result, addend)
        addend = _ed25519_add(addend, addend)
        scalar >>= 1
    return result


def _ed25519_encode(point: tuple[int, int]) -> bytes:
    x, y = point
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def _ed25519_public_from_seed(seed: bytes) -> bytes:
    digest = hashlib.sha512(seed).digest()
    scalar = bytearray(digest[:32])
    scalar[0] &= 248
    scalar[31] &= 63
    scalar[31] |= 64
    point = _ed25519_scalar_mult(int.from_bytes(scalar, "little"), _ED25519_BASE)
    return _ed25519_encode(point)


def _bech32_polymod(values: Sequence[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit_index, generator in enumerate(generators):
            if (top >> bit_index) & 1:
                checksum ^= generator
    return checksum


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def _convert_bits(data: bytes, from_bits: int, to_bits: int, pad: bool) -> list[int]:
    acc = 0
    bits = 0
    output: list[int] = []
    maxv = (1 << to_bits) - 1
    for value in data:
        if value >> from_bits:
            raise ValueError("input value exceeds bit width")
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            output.append((acc >> bits) & maxv)
    if pad:
        if bits:
            output.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        raise ValueError("invalid leftover bits")
    return output


def _bech32m_encode(hrp: str, data: bytes) -> str:
    values = _convert_bits(data, 8, 5, pad=True)
    checksum_input = _bech32_hrp_expand(hrp) + values + [0] * 6
    polymod = _bech32_polymod(checksum_input) ^ 0x2BC830A3
    checksum = [((polymod >> (5 * (5 - index))) & 31) for index in range(6)]
    encoded = "".join(_BECH32_CHARSET[value] for value in [*values, *checksum])
    return f"{hrp}1{encoded}"


def _encode_address(
    spending_public_key_x: int,
    spending_public_key_y: int,
    viewing_public_key: bytes,
    *,
    use_chain: bool,
    chain_type: int,
    chain_id: int,
) -> str:
    payload = bytearray(73)
    payload[0] = 0x01
    payload[1:33] = spending_public_key_y.to_bytes(32, "little")
    payload[32] |= (spending_public_key_x & 1) << 7
    if use_chain:
        network_id = bytearray([chain_type]) + bytearray(chain_id.to_bytes(7, "big"))
    else:
        network_id = bytearray(b"\xFF" * 8)
    for index, byte in enumerate(b"railgun"):
        network_id[index] ^= byte
    payload[33:41] = network_id
    payload[41:73] = viewing_public_key
    return _bech32m_encode("0zk", bytes(payload))
