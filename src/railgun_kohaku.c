#include "railgun_kohaku.h"

#include <ctype.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))

static const uint64_t BLAKE512_IV[8] = {
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

static const uint8_t BLAKE512_SIGMA[16][16] = {
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
  { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
  { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
  { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
  { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
  { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
  { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
  { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
  { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
  { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
  { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
};

static const uint64_t BLAKE512_C[16] = {
  0x243f6a8885a308d3ULL, 0x13198a2e03707344ULL,
  0xa4093822299f31d0ULL, 0x082efa98ec4e6c89ULL,
  0x452821e638d01377ULL, 0xbe5466cf34e90c6cULL,
  0xc0ac29b7c97c50ddULL, 0x3f84d5b5b5470917ULL,
  0x9216d5d98979fb1bULL, 0xd1310ba698dfb5acULL,
  0x2ffd72dbd01adfb7ULL, 0xb8e1afed6a267e96ULL,
  0xba7c9045f12c7f99ULL, 0x24a19947b3916cf7ULL,
  0x0801f2e2858efc16ULL, 0x636920d871574e69ULL,
};

typedef struct blake512_ctx {
  uint64_t h[8];
  uint64_t s[4];
  uint64_t t[2];
  uint8_t buffer[128];
  size_t buflen;
} blake512_ctx;

typedef struct poseidon_params {
  size_t t;
  size_t rf;
  size_t rp;
} poseidon_params_t;

typedef struct babyjub_point {
  BIGNUM *x;
  BIGNUM *y;
} babyjub_point_t;

static void set_error(char error[RAILGUN_ERROR_BUF], const char *message) {
  if (error == NULL) {
    return;
  }
  snprintf(error, RAILGUN_ERROR_BUF, "%s", message);
}

static int copy_string(char *dst, size_t dst_len, const char *src) {
  size_t len;
  if (dst == NULL || src == NULL || dst_len == 0) {
    return 0;
  }
  len = strlen(src);
  if (len + 1 > dst_len) {
    return 0;
  }
  memcpy(dst, src, len + 1);
  return 1;
}

static int address_is_valid(const char *address) {
  return address != NULL && address[0] != '\0' && strlen(address) < RAILGUN_ADDRESS_BUF;
}

static void sha256_hex(const uint8_t *data, size_t len, char out[RAILGUN_TX_ID_BUF]) {
  static const char digits[] = "0123456789abcdef";
  uint8_t digest[SHA256_DIGEST_LENGTH];
  size_t i;

  SHA256(data, len, digest);
  for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    out[i * 2] = digits[(digest[i] >> 4) & 0x0f];
    out[(i * 2) + 1] = digits[digest[i] & 0x0f];
  }
  out[RAILGUN_TX_ID_BUF - 1] = '\0';
}

static railgun_kohaku_ledger_entry_t *ledger_find_entry(
  const railgun_kohaku_ledger_t *ledger,
  const char *address
) {
  size_t i;

  if (ledger == NULL || address == NULL) {
    return NULL;
  }
  for (i = 0; i < ledger->count; i++) {
    if (strcmp(ledger->entries[i].address, address) == 0) {
      return &ledger->entries[i];
    }
  }
  return NULL;
}

static railgun_kohaku_ledger_entry_t *ledger_get_or_create_entry(
  railgun_kohaku_ledger_t *ledger,
  const char *address,
  char error[RAILGUN_ERROR_BUF]
) {
  railgun_kohaku_ledger_entry_t *entry = ledger_find_entry(ledger, address);

  if (entry != NULL) {
    return entry;
  }
  if (ledger == NULL || ledger->entries == NULL) {
    set_error(error, "ledger is required");
    return NULL;
  }
  if (ledger->count >= ledger->capacity) {
    set_error(error, "ledger capacity exceeded");
    return NULL;
  }
  entry = &ledger->entries[ledger->count++];
  memset(entry, 0, sizeof(*entry));
  if (!copy_string(entry->address, sizeof(entry->address), address)) {
    ledger->count--;
    set_error(error, "address is too long");
    return NULL;
  }
  return entry;
}

static int populate_transfer_receipt(
  railgun_kohaku_transfer_receipt_t *out,
  const char *from_address,
  const char *to_address,
  uint64_t amount,
  uint64_t sender_balance,
  uint64_t recipient_balance,
  char error[RAILGUN_ERROR_BUF]
) {
  char payload[RAILGUN_ADDRESS_BUF * 2 + 80];
  int written;

  if (out == NULL) {
    set_error(error, "transfer receipt output is required");
    return 0;
  }
  memset(out, 0, sizeof(*out));
  if (!copy_string(out->from_address, sizeof(out->from_address), from_address) ||
      !copy_string(out->to_address, sizeof(out->to_address), to_address)) {
    set_error(error, "address is too long");
    return 0;
  }
  out->amount = amount;
  out->sender_balance = sender_balance;
  out->recipient_balance = recipient_balance;

  written = snprintf(
    payload,
    sizeof(payload),
    "%s|%s|%llu|%llu|%llu",
    from_address,
    to_address,
    (unsigned long long)amount,
    (unsigned long long)sender_balance,
    (unsigned long long)recipient_balance
  );
  if (written < 0 || (size_t)written >= sizeof(payload)) {
    set_error(error, "receipt payload encoding failed");
    return 0;
  }
  sha256_hex((const uint8_t *)payload, (size_t)written, out->tx_id);
  return 1;
}

static uint64_t rotr64(uint64_t x, uint32_t n) {
  return (x >> n) | (x << (64 - n));
}

static uint64_t load64_be(const uint8_t *src) {
  return ((uint64_t)src[0] << 56) |
         ((uint64_t)src[1] << 48) |
         ((uint64_t)src[2] << 40) |
         ((uint64_t)src[3] << 32) |
         ((uint64_t)src[4] << 24) |
         ((uint64_t)src[5] << 16) |
         ((uint64_t)src[6] << 8) |
         ((uint64_t)src[7]);
}

static void store64_be(uint8_t *dst, uint64_t value) {
  dst[0] = (uint8_t)(value >> 56);
  dst[1] = (uint8_t)(value >> 48);
  dst[2] = (uint8_t)(value >> 40);
  dst[3] = (uint8_t)(value >> 32);
  dst[4] = (uint8_t)(value >> 24);
  dst[5] = (uint8_t)(value >> 16);
  dst[6] = (uint8_t)(value >> 8);
  dst[7] = (uint8_t)value;
}

static void blake512_g(uint64_t v[16], int a, int b, int c, int d, uint64_t mx, uint64_t my, uint64_t cx, uint64_t cy) {
  v[a] = v[a] + v[b] + (mx ^ cy);
  v[d] = rotr64(v[d] ^ v[a], 32);
  v[c] = v[c] + v[d];
  v[b] = rotr64(v[b] ^ v[c], 25);
  v[a] = v[a] + v[b] + (my ^ cx);
  v[d] = rotr64(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d];
  v[b] = rotr64(v[b] ^ v[c], 11);
}

static void blake512_compress(blake512_ctx *ctx, const uint8_t block[128], int last) {
  uint64_t m[16];
  uint64_t v[16];
  size_t i;

  for (i = 0; i < 16; i++) {
    m[i] = load64_be(block + (i * 8));
  }
  for (i = 0; i < 8; i++) {
    v[i] = ctx->h[i];
  }
  v[8] = ctx->s[0] ^ BLAKE512_C[0];
  v[9] = ctx->s[1] ^ BLAKE512_C[1];
  v[10] = ctx->s[2] ^ BLAKE512_C[2];
  v[11] = ctx->s[3] ^ BLAKE512_C[3];
  v[12] = ctx->t[0] ^ BLAKE512_C[4];
  v[13] = ctx->t[0] ^ BLAKE512_C[5];
  v[14] = ctx->t[1] ^ BLAKE512_C[6];
  v[15] = ctx->t[1] ^ BLAKE512_C[7];
  if (last) {
    v[14] = ~v[14];
  }

  for (i = 0; i < 16; i++) {
    const uint8_t *s = BLAKE512_SIGMA[i];
    blake512_g(v, 0, 4, 8, 12, m[s[0]], m[s[1]], BLAKE512_C[s[0]], BLAKE512_C[s[1]]);
    blake512_g(v, 1, 5, 9, 13, m[s[2]], m[s[3]], BLAKE512_C[s[2]], BLAKE512_C[s[3]]);
    blake512_g(v, 2, 6, 10, 14, m[s[4]], m[s[5]], BLAKE512_C[s[4]], BLAKE512_C[s[5]]);
    blake512_g(v, 3, 7, 11, 15, m[s[6]], m[s[7]], BLAKE512_C[s[6]], BLAKE512_C[s[7]]);
    blake512_g(v, 0, 5, 10, 15, m[s[8]], m[s[9]], BLAKE512_C[s[8]], BLAKE512_C[s[9]]);
    blake512_g(v, 1, 6, 11, 12, m[s[10]], m[s[11]], BLAKE512_C[s[10]], BLAKE512_C[s[11]]);
    blake512_g(v, 2, 7, 8, 13, m[s[12]], m[s[13]], BLAKE512_C[s[12]], BLAKE512_C[s[13]]);
    blake512_g(v, 3, 4, 9, 14, m[s[14]], m[s[15]], BLAKE512_C[s[14]], BLAKE512_C[s[15]]);
  }

  for (i = 0; i < 8; i++) {
    ctx->h[i] ^= ctx->s[i & 3] ^ v[i] ^ v[i + 8];
  }
}

static void blake512_init(blake512_ctx *ctx) {
  memset(ctx, 0, sizeof(*ctx));
  memcpy(ctx->h, BLAKE512_IV, sizeof(BLAKE512_IV));
}

static void blake512_update(blake512_ctx *ctx, const uint8_t *data, size_t len) {
  while (len > 0) {
    size_t take = 128 - ctx->buflen;
    if (take > len) {
      take = len;
    }
    memcpy(ctx->buffer + ctx->buflen, data, take);
    ctx->buflen += take;
    data += take;
    len -= take;
    if (ctx->buflen == 128) {
      ctx->t[0] += 1024ULL;
      if (ctx->t[0] < 1024ULL) {
        ctx->t[1] += 1ULL;
      }
      blake512_compress(ctx, ctx->buffer, 0);
      ctx->buflen = 0;
    }
  }
}

static void blake512_final(blake512_ctx *ctx, uint8_t out[64]) {
  uint8_t block[128];
  uint64_t bit_len_hi = ctx->t[1];
  uint64_t bit_len_lo = ctx->t[0] + ((uint64_t)ctx->buflen * 8ULL);
  size_t i;

  if (bit_len_lo < ctx->t[0]) {
    bit_len_hi += 1ULL;
  }
  memset(block, 0, sizeof(block));
  if (ctx->buflen > 0) {
    memcpy(block, ctx->buffer, ctx->buflen);
  }
  block[ctx->buflen] = 0x80;
  if (ctx->buflen > 111) {
    blake512_compress(ctx, block, 0);
    memset(block, 0, sizeof(block));
  }
  block[111] |= 0x01;
  for (i = 0; i < 8; i++) {
    block[119 - i] = (uint8_t)(bit_len_hi >> (8 * i));
    block[127 - i] = (uint8_t)(bit_len_lo >> (8 * i));
  }
  ctx->t[0] = bit_len_lo;
  ctx->t[1] = bit_len_hi;
  blake512_compress(ctx, block, 1);
  for (i = 0; i < 8; i++) {
    store64_be(out + (i * 8), ctx->h[i]);
  }
}

static void blake512_hash(const uint8_t *data, size_t len, uint8_t out[64]) {
  blake512_ctx ctx;
  blake512_init(&ctx);
  blake512_update(&ctx, data, len);
  blake512_final(&ctx, out);
}

static BIGNUM *bn_from_hex(const char *hex) {
  BIGNUM *bn = NULL;
  BN_hex2bn(&bn, hex);
  return bn;
}

static int bn_to_fixed_be(const BIGNUM *bn, uint8_t *out, size_t len) {
  if (BN_bn2binpad(bn, out, (int)len) != (int)len) {
    return 0;
  }
  return 1;
}

static int bn_to_fixed_le(const BIGNUM *bn, uint8_t *out, size_t len) {
  uint8_t buffer[32];
  size_t i;

  if (len > sizeof(buffer) || !bn_to_fixed_be(bn, buffer, len)) {
    return 0;
  }
  for (i = 0; i < len; i++) {
    out[i] = buffer[len - 1 - i];
  }
  OPENSSL_cleanse(buffer, sizeof(buffer));
  return 1;
}

static int bn_to_hex_dec(const BIGNUM *bn, char *out, size_t out_len) {
  char *tmp = BN_bn2dec(bn);
  if (tmp == NULL) {
    return 0;
  }
  if (strlen(tmp) + 1 > out_len) {
    OPENSSL_free(tmp);
    return 0;
  }
  memcpy(out, tmp, strlen(tmp) + 1);
  OPENSSL_free(tmp);
  return 1;
}

static int mnemonic_salt(const char *passphrase, char **salt_out) {
  size_t salt_len = strlen("mnemonic") + (passphrase ? strlen(passphrase) : 0);
  char *salt = (char *)malloc(salt_len + 1);
  if (salt == NULL) {
    return 0;
  }
  strcpy(salt, "mnemonic");
  if (passphrase != NULL) {
    strcat(salt, passphrase);
  }
  *salt_out = salt;
  return 1;
}

int railgun_kohaku_seed_from_mnemonic(
  const char *mnemonic,
  const char *passphrase,
  uint8_t seed_out[64],
  char error[RAILGUN_ERROR_BUF]
) {
  char *salt;
  if (mnemonic == NULL || seed_out == NULL) {
    set_error(error, "mnemonic and seed_out are required");
    return 0;
  }
  if (!mnemonic_salt(passphrase, &salt)) {
    set_error(error, "failed to allocate mnemonic salt");
    return 0;
  }
  if (PKCS5_PBKDF2_HMAC(
        mnemonic,
        (int)strlen(mnemonic),
        (const unsigned char *)salt,
        (int)strlen(salt),
        2048,
        EVP_sha512(),
        64,
        seed_out) != 1) {
    free(salt);
    set_error(error, "PBKDF2-HMAC-SHA512 failed");
    return 0;
  }
  free(salt);
  if (error) {
    error[0] = '\0';
  }
  return 1;
}

static int hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[64]) {
  unsigned int out_len = 0;
  return HMAC(EVP_sha512(), key, (int)key_len, msg, msg_len, out, &out_len) != NULL && out_len == 64;
}

static int child_key_derivation_hardened(
  const uint8_t parent_key[32],
  const uint8_t parent_chain_code[32],
  uint32_t index,
  uint8_t child_key[32],
  uint8_t child_chain_code[32]
) {
  static const char *SECP256K1_ORDER_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
  uint8_t data[37];
  uint8_t i64[64];
  BIGNUM *n = NULL;
  BIGNUM *parent = NULL;
  BIGNUM *il = NULL;
  BN_CTX *ctx = NULL;
  int ok = 0;

  data[0] = 0x00;
  memcpy(data + 1, parent_key, 32);
  data[33] = (uint8_t)(index >> 24);
  data[34] = (uint8_t)(index >> 16);
  data[35] = (uint8_t)(index >> 8);
  data[36] = (uint8_t)index;

  if (!hmac_sha512(parent_chain_code, 32, data, sizeof(data), i64)) {
    return 0;
  }

  ctx = BN_CTX_new();
  n = bn_from_hex(SECP256K1_ORDER_HEX);
  parent = BN_bin2bn(parent_key, 32, NULL);
  il = BN_bin2bn(i64, 32, NULL);
  if (ctx == NULL || n == NULL || parent == NULL || il == NULL) {
    goto cleanup;
  }
  if (!BN_mod_add(parent, parent, il, n, ctx)) {
    goto cleanup;
  }
  if (!bn_to_fixed_be(parent, child_key, 32)) {
    goto cleanup;
  }
  memcpy(child_chain_code, i64 + 32, 32);
  ok = 1;

cleanup:
  BN_free(n);
  BN_free(parent);
  BN_free(il);
  BN_CTX_free(ctx);
  OPENSSL_cleanse(i64, sizeof(i64));
  return ok;
}

static int child_key_derivation_ed25519_hardened(
  const uint8_t parent_key[32],
  const uint8_t parent_chain_code[32],
  uint32_t index,
  uint8_t child_key[32],
  uint8_t child_chain_code[32]
) {
  uint8_t data[37];
  uint8_t i64[64];

  data[0] = 0x00;
  memcpy(data + 1, parent_key, 32);
  data[33] = (uint8_t)(index >> 24);
  data[34] = (uint8_t)(index >> 16);
  data[35] = (uint8_t)(index >> 8);
  data[36] = (uint8_t)index;

  if (!hmac_sha512(parent_chain_code, 32, data, sizeof(data), i64)) {
    return 0;
  }

  memcpy(child_key, i64, 32);
  memcpy(child_chain_code, i64 + 32, 32);
  OPENSSL_cleanse(i64, sizeof(i64));
  return 1;
}

int railgun_kohaku_ledger_init(
  railgun_kohaku_ledger_t *ledger,
  railgun_kohaku_ledger_entry_t *entries,
  size_t capacity,
  char error[RAILGUN_ERROR_BUF]
) {
  if (ledger == NULL) {
    set_error(error, "ledger is required");
    return 0;
  }
  if (entries == NULL && capacity != 0) {
    set_error(error, "ledger entries are required");
    return 0;
  }
  ledger->entries = entries;
  ledger->capacity = capacity;
  ledger->count = 0;
  if (entries != NULL && capacity != 0) {
    memset(entries, 0, capacity * sizeof(*entries));
  }
  if (error != NULL) {
    error[0] = '\0';
  }
  return 1;
}

int railgun_kohaku_ledger_set_balance(
  railgun_kohaku_ledger_t *ledger,
  const char *address,
  uint64_t balance,
  char error[RAILGUN_ERROR_BUF]
) {
  railgun_kohaku_ledger_entry_t *entry;

  if (!address_is_valid(address)) {
    set_error(error, "address is required");
    return 0;
  }
  entry = ledger_get_or_create_entry(ledger, address, error);
  if (entry == NULL) {
    return 0;
  }
  entry->balance = balance;
  if (error != NULL) {
    error[0] = '\0';
  }
  return 1;
}

int railgun_kohaku_check_account_balance(
  const railgun_kohaku_ledger_t *ledger,
  const char *address,
  railgun_kohaku_balance_info_t *out,
  char error[RAILGUN_ERROR_BUF]
) {
  railgun_kohaku_ledger_entry_t *entry;

  if (ledger == NULL) {
    set_error(error, "ledger is required");
    return 0;
  }
  if (!address_is_valid(address)) {
    set_error(error, "address is required");
    return 0;
  }
  if (out == NULL) {
    set_error(error, "balance output is required");
    return 0;
  }
  memset(out, 0, sizeof(*out));
  entry = ledger_find_entry(ledger, address);
  if (entry != NULL) {
    out->balance = entry->balance;
  }
  out->is_active = out->balance > 0 ? 1 : 0;
  if (!copy_string(out->status, sizeof(out->status), out->is_active ? "active" : "inactive")) {
    set_error(error, "status encoding failed");
    return 0;
  }
  if (error != NULL) {
    error[0] = '\0';
  }
  return 1;
}

int railgun_kohaku_send_funds(
  railgun_kohaku_ledger_t *ledger,
  const char *from_address,
  const char *to_address,
  uint64_t amount,
  railgun_kohaku_transfer_receipt_t *out,
  char error[RAILGUN_ERROR_BUF]
) {
  railgun_kohaku_ledger_entry_t *sender;
  railgun_kohaku_ledger_entry_t *recipient;

  if (!address_is_valid(from_address) || !address_is_valid(to_address)) {
    set_error(error, "from and to addresses are required");
    return 0;
  }
  if (strcmp(from_address, to_address) == 0) {
    set_error(error, "from and to addresses must differ");
    return 0;
  }
  if (amount == 0) {
    set_error(error, "amount must be greater than zero");
    return 0;
  }
  sender = ledger_get_or_create_entry(ledger, from_address, error);
  if (sender == NULL) {
    return 0;
  }
  recipient = ledger_get_or_create_entry(ledger, to_address, error);
  if (recipient == NULL) {
    return 0;
  }
  if (sender->balance < amount) {
    set_error(error, "insufficient funds");
    return 0;
  }
  if (UINT64_MAX - recipient->balance < amount) {
    set_error(error, "recipient balance overflow");
    return 0;
  }
  sender->balance -= amount;
  recipient->balance += amount;
  if (!populate_transfer_receipt(out, from_address, to_address, amount, sender->balance, recipient->balance, error)) {
    return 0;
  }
  if (error != NULL) {
    error[0] = '\0';
  }
  return 1;
}

int railgun_kohaku_receive_funds(
  railgun_kohaku_ledger_t *ledger,
  const char *to_address,
  uint64_t amount,
  const char *source_address,
  railgun_kohaku_transfer_receipt_t *out,
  char error[RAILGUN_ERROR_BUF]
) {
  railgun_kohaku_ledger_entry_t *recipient;
  const char *source = source_address;

  if (!address_is_valid(to_address)) {
    set_error(error, "to address is required");
    return 0;
  }
  if (amount == 0) {
    set_error(error, "amount must be greater than zero");
    return 0;
  }
  if (source == NULL || source[0] == '\0') {
    source = "external";
  } else if (strlen(source) >= RAILGUN_ADDRESS_BUF) {
    set_error(error, "source address is too long");
    return 0;
  }
  if (strcmp(source, to_address) == 0) {
    set_error(error, "source and destination addresses must differ");
    return 0;
  }
  recipient = ledger_get_or_create_entry(ledger, to_address, error);
  if (recipient == NULL) {
    return 0;
  }
  if (UINT64_MAX - recipient->balance < amount) {
    set_error(error, "recipient balance overflow");
    return 0;
  }
  recipient->balance += amount;
  if (!populate_transfer_receipt(out, source, to_address, amount, 0, recipient->balance, error)) {
    return 0;
  }
  if (error != NULL) {
    error[0] = '\0';
  }
  return 1;
}

static int derive_path_hardened(
  const uint8_t seed[64],
  const uint32_t *segments,
  size_t segment_count,
  uint8_t out_key[32],
  uint8_t out_chain_code[32]
) {
  uint8_t i64[64];
  uint8_t cur_key[32];
  uint8_t cur_chain[32];
  size_t i;

  if (!hmac_sha512((const uint8_t *)"Bitcoin seed", strlen("Bitcoin seed"), seed, 64, i64)) {
    return 0;
  }
  memcpy(cur_key, i64, 32);
  memcpy(cur_chain, i64 + 32, 32);
  OPENSSL_cleanse(i64, sizeof(i64));

  for (i = 0; i < segment_count; i++) {
    if (!child_key_derivation_hardened(cur_key, cur_chain, 0x80000000U + segments[i], cur_key, cur_chain)) {
      OPENSSL_cleanse(cur_key, sizeof(cur_key));
      OPENSSL_cleanse(cur_chain, sizeof(cur_chain));
      return 0;
    }
  }

  memcpy(out_key, cur_key, 32);
  memcpy(out_chain_code, cur_chain, 32);
  OPENSSL_cleanse(cur_key, sizeof(cur_key));
  OPENSSL_cleanse(cur_chain, sizeof(cur_chain));
  return 1;
}

static int derive_path_ed25519_hardened(
  const uint8_t seed[64],
  const uint32_t *segments,
  size_t segment_count,
  uint8_t out_key[32],
  uint8_t out_chain_code[32]
) {
  uint8_t i64[64];
  uint8_t cur_key[32];
  uint8_t cur_chain[32];
  size_t i;

  if (!hmac_sha512((const uint8_t *)"ed25519 seed", strlen("ed25519 seed"), seed, 64, i64)) {
    return 0;
  }
  memcpy(cur_key, i64, 32);
  memcpy(cur_chain, i64 + 32, 32);
  OPENSSL_cleanse(i64, sizeof(i64));

  for (i = 0; i < segment_count; i++) {
    if (!child_key_derivation_ed25519_hardened(
          cur_key, cur_chain, 0x80000000U + segments[i], cur_key, cur_chain)) {
      OPENSSL_cleanse(cur_key, sizeof(cur_key));
      OPENSSL_cleanse(cur_chain, sizeof(cur_chain));
      return 0;
    }
  }

  memcpy(out_key, cur_key, 32);
  memcpy(out_chain_code, cur_chain, 32);
  OPENSSL_cleanse(cur_key, sizeof(cur_key));
  OPENSSL_cleanse(cur_chain, sizeof(cur_chain));
  return 1;
}

static int ed25519_public_from_seed(const uint8_t seed[32], uint8_t public_key[32]) {
  EVP_PKEY *pkey = NULL;
  size_t len = 32;
  int ok = 0;

  pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
  if (pkey == NULL) {
    return 0;
  }
  if (EVP_PKEY_get_raw_public_key(pkey, public_key, &len) != 1 || len != 32) {
    goto cleanup;
  }
  ok = 1;

cleanup:
  EVP_PKEY_free(pkey);
  return ok;
}

static int bn_mod_exp5(BIGNUM *r, const BIGNUM *a, const BIGNUM *mod, BN_CTX *ctx) {
  BIGNUM *tmp = BN_new();
  if (tmp == NULL) {
    return 0;
  }
  if (!BN_mod_mul(tmp, a, a, mod, ctx) ||
      !BN_mod_mul(tmp, tmp, tmp, mod, ctx) ||
      !BN_mod_mul(r, tmp, a, mod, ctx)) {
    BN_free(tmp);
    return 0;
  }
  BN_free(tmp);
  return 1;
}

static void babyjub_point_init(babyjub_point_t *p) {
  p->x = BN_new();
  p->y = BN_new();
}

static void babyjub_point_free(babyjub_point_t *p) {
  BN_free(p->x);
  BN_free(p->y);
}

static int babyjub_point_copy(babyjub_point_t *dst, const babyjub_point_t *src) {
  return BN_copy(dst->x, src->x) != NULL && BN_copy(dst->y, src->y) != NULL;
}

static int babyjub_identity(babyjub_point_t *p) {
  BN_zero(p->x);
  BN_one(p->y);
  return 1;
}

static int babyjub_add(
  babyjub_point_t *out,
  const babyjub_point_t *p,
  const babyjub_point_t *q,
  const BIGNUM *field,
  const BIGNUM *curve_a,
  const BIGNUM *curve_d,
  BN_CTX *ctx
) {
  BIGNUM *x1y2 = BN_new();
  BIGNUM *y1x2 = BN_new();
  BIGNUM *x1x2 = BN_new();
  BIGNUM *y1y2 = BN_new();
  BIGNUM *dxxyy = BN_new();
  BIGNUM *num_x = BN_new();
  BIGNUM *den_x = BN_new();
  BIGNUM *num_y = BN_new();
  BIGNUM *den_y = BN_new();
  BIGNUM *inv = NULL;
  int ok = 0;

  if (x1y2 == NULL || y1x2 == NULL || x1x2 == NULL || y1y2 == NULL ||
      dxxyy == NULL || num_x == NULL || den_x == NULL || num_y == NULL || den_y == NULL) {
    goto cleanup;
  }

  if (!BN_mod_mul(x1y2, p->x, q->y, field, ctx) ||
      !BN_mod_mul(y1x2, p->y, q->x, field, ctx) ||
      !BN_mod_mul(x1x2, p->x, q->x, field, ctx) ||
      !BN_mod_mul(y1y2, p->y, q->y, field, ctx) ||
      !BN_mod_mul(dxxyy, x1x2, y1y2, field, ctx) ||
      !BN_mod_mul(dxxyy, dxxyy, curve_d, field, ctx) ||
      !BN_mod_add(num_x, x1y2, y1x2, field, ctx) ||
      !BN_mod_add(den_x, dxxyy, BN_value_one(), field, ctx) ||
      !BN_mod_mul(num_y, curve_a, x1x2, field, ctx) ||
      !BN_mod_sub(num_y, y1y2, num_y, field, ctx) ||
      !BN_mod_sub(den_y, BN_value_one(), dxxyy, field, ctx)) {
    goto cleanup;
  }

  inv = BN_mod_inverse(NULL, den_x, field, ctx);
  if (inv == NULL || !BN_mod_mul(out->x, num_x, inv, field, ctx)) {
    goto cleanup;
  }
  BN_free(inv);
  inv = BN_mod_inverse(NULL, den_y, field, ctx);
  if (inv == NULL || !BN_mod_mul(out->y, num_y, inv, field, ctx)) {
    goto cleanup;
  }
  ok = 1;

cleanup:
  BN_free(x1y2);
  BN_free(y1x2);
  BN_free(x1x2);
  BN_free(y1y2);
  BN_free(dxxyy);
  BN_free(num_x);
  BN_free(den_x);
  BN_free(num_y);
  BN_free(den_y);
  BN_free(inv);
  return ok;
}

static int babyjub_mul_base8(
  babyjub_point_t *out,
  const BIGNUM *scalar,
  const BIGNUM *field,
  const BIGNUM *curve_a,
  const BIGNUM *curve_d,
  BN_CTX *ctx
) {
  static const char *BASE8_X = "5299619240641551281634865583518297030282874472190772894086521144482721001553";
  static const char *BASE8_Y = "16950150798460657717958625567821834550301663161624707787222815936182638968203";
  babyjub_point_t acc;
  babyjub_point_t base;
  babyjub_point_t tmp;
  int bits;
  int i;
  int ok = 0;

  babyjub_point_init(&acc);
  babyjub_point_init(&base);
  babyjub_point_init(&tmp);
  if (acc.x == NULL || base.x == NULL || tmp.x == NULL) {
    goto cleanup;
  }
  if (!babyjub_identity(&acc)) {
    goto cleanup;
  }
  if (!BN_dec2bn(&base.x, BASE8_X) || !BN_dec2bn(&base.y, BASE8_Y)) {
    goto cleanup;
  }

  bits = BN_num_bits(scalar);
  for (i = 0; i < bits; i++) {
    if (BN_is_bit_set(scalar, i)) {
      if (!babyjub_add(&tmp, &acc, &base, field, curve_a, curve_d, ctx) || !babyjub_point_copy(&acc, &tmp)) {
        goto cleanup;
      }
    }
    if (!babyjub_add(&tmp, &base, &base, field, curve_a, curve_d, ctx) || !babyjub_point_copy(&base, &tmp)) {
      goto cleanup;
    }
  }
  if (!babyjub_point_copy(out, &acc)) {
    goto cleanup;
  }
  ok = 1;

cleanup:
  babyjub_point_free(&acc);
  babyjub_point_free(&base);
  babyjub_point_free(&tmp);
  return ok;
}

static int derive_spending_public_key(const uint8_t private_key[32], BIGNUM **out_x, BIGNUM **out_y) {
  static const char *BN254_FIELD = "30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001";
  static const char *BABYJUB_A = "168700";
  static const char *BABYJUB_D = "168696";
  uint8_t h[64];
  uint8_t pruned[32];
  uint8_t le_scalar[32];
  BIGNUM *field = NULL;
  BIGNUM *curve_a = NULL;
  BIGNUM *curve_d = NULL;
  BIGNUM *scalar = NULL;
  BN_CTX *ctx = NULL;
  babyjub_point_t pub;
  size_t i;
  int ok = 0;

  blake512_hash(private_key, 32, h);
  memcpy(pruned, h, 32);
  pruned[0] &= 0xf8U;
  pruned[31] &= 0x7fU;
  pruned[31] |= 0x40U;
  for (i = 0; i < 32; i++) {
    le_scalar[i] = pruned[31 - i];
  }

  babyjub_point_init(&pub);
  ctx = BN_CTX_new();
  field = bn_from_hex(BN254_FIELD);
  curve_a = bn_from_hex(BABYJUB_A);
  curve_d = bn_from_hex(BABYJUB_D);
  scalar = BN_bin2bn(le_scalar, 32, NULL);
  if (ctx == NULL || field == NULL || curve_a == NULL || curve_d == NULL || scalar == NULL || pub.x == NULL) {
    goto cleanup;
  }
  if (!BN_rshift(scalar, scalar, 3)) {
    goto cleanup;
  }
  if (!babyjub_mul_base8(&pub, scalar, field, curve_a, curve_d, ctx)) {
    goto cleanup;
  }
  *out_x = BN_dup(pub.x);
  *out_y = BN_dup(pub.y);
  ok = (*out_x != NULL && *out_y != NULL);

cleanup:
  OPENSSL_cleanse(h, sizeof(h));
  OPENSSL_cleanse(pruned, sizeof(pruned));
  OPENSSL_cleanse(le_scalar, sizeof(le_scalar));
  babyjub_point_free(&pub);
  BN_free(field);
  BN_free(curve_a);
  BN_free(curve_d);
  BN_free(scalar);
  BN_CTX_free(ctx);
  return ok;
}

static size_t poseidon_partial_rounds(size_t t) {
  static const size_t partials[] = { 56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65 };
  if (t < 2 || t > 13) {
    return 0;
  }
  return partials[t - 2];
}

static int grain_bit(uint8_t state[80]) {
  int bit = state[0] ^ state[13] ^ state[23] ^ state[38] ^ state[51] ^ state[62];
  memmove(state, state + 1, 79);
  state[79] = (uint8_t)(bit & 1);
  return bit & 1;
}

static int poseidon_generate_constants(BIGNUM ***constants_out, size_t *count_out, const poseidon_params_t *params, const BIGNUM *field, BN_CTX *ctx) {
  uint8_t state[80];
  BIGNUM **constants = NULL;
  BIGNUM *candidate = NULL;
  size_t total = (params->rf + params->rp) * params->t;
  size_t found = 0;
  size_t i;

  memset(state, 0, sizeof(state));
  state[1] = 1;
  state[5] = 1;
  for (i = 0; i < 12; i++) {
    state[6 + i] = (uint8_t)((255U >> (11 - i)) & 1U);
    state[18 + i] = (uint8_t)((params->t >> (11 - i)) & 1U);
  }
  for (i = 0; i < 10; i++) {
    state[30 + i] = (uint8_t)((params->rf >> (9 - i)) & 1U);
    state[40 + i] = (uint8_t)((params->rp >> (9 - i)) & 1U);
  }
  memset(state + 50, 1, 30);
  for (i = 0; i < 160; i++) {
    grain_bit(state);
  }

  constants = (BIGNUM **)calloc(total, sizeof(BIGNUM *));
  candidate = BN_new();
  if (constants == NULL || candidate == NULL) {
    goto fail;
  }

  while (found < total) {
    uint8_t bits[255];
    uint8_t bytes[32];
    size_t bits_len = 0;
    memset(bytes, 0, sizeof(bytes));
    while (bits_len < 255) {
      int bit1 = grain_bit(state);
      int bit2 = grain_bit(state);
      if (bit1) {
        bits[bits_len++] = (uint8_t)bit2;
      }
    }
    for (i = 0; i < 255; i++) {
      if (bits[i]) {
        bytes[i / 8] |= (uint8_t)(1U << (7 - (i % 8)));
      }
    }
    if (BN_bin2bn(bytes, sizeof(bytes), candidate) == NULL) {
      goto fail;
    }
    if (BN_cmp(candidate, field) < 0) {
      constants[found] = BN_dup(candidate);
      if (constants[found] == NULL) {
        goto fail;
      }
      found++;
    }
  }

  BN_free(candidate);
  *constants_out = constants;
  *count_out = total;
  (void)ctx;
  return 1;

fail:
  if (constants != NULL) {
    for (i = 0; i < total; i++) {
      BN_free(constants[i]);
    }
    free(constants);
  }
  BN_free(candidate);
  return 0;
}

static int poseidon_generate_mds(BIGNUM ***mds_out, size_t t, const BIGNUM *field, BN_CTX *ctx) {
  BIGNUM **mds = (BIGNUM **)calloc(t * t, sizeof(BIGNUM *));
  size_t i;
  size_t j;
  int ok = 0;
  if (mds == NULL) {
    return 0;
  }
  for (i = 0; i < t; i++) {
    for (j = 0; j < t; j++) {
      BIGNUM *sum = BN_new();
      BIGNUM *inv;
      if (sum == NULL) {
        goto cleanup;
      }
      if (!BN_set_word(sum, (BN_ULONG)(i + t + j))) {
        BN_free(sum);
        goto cleanup;
      }
      inv = BN_mod_inverse(NULL, sum, field, ctx);
      BN_free(sum);
      if (inv == NULL) {
        goto cleanup;
      }
      mds[i * t + j] = inv;
    }
  }
  ok = 1;

cleanup:
  if (!ok) {
    for (i = 0; i < t * t; i++) {
      BN_free(mds[i]);
    }
    free(mds);
  } else {
    *mds_out = mds;
  }
  return ok;
}

static int poseidon_hash_bn(BIGNUM **out, BIGNUM *const *inputs, size_t input_count) {
  static const char *BN254_FIELD = "30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001";
  BIGNUM *field = NULL;
  BIGNUM **constants = NULL;
  BIGNUM **mds = NULL;
  BIGNUM **state = NULL;
  BIGNUM **next_state = NULL;
  BN_CTX *ctx = NULL;
  poseidon_params_t params;
  size_t const_count = 0;
  size_t rounds;
  size_t r;
  size_t i;
  size_t j;
  int ok = 0;

  params.t = input_count + 1;
  params.rf = 8;
  params.rp = poseidon_partial_rounds(params.t);
  if (params.rp == 0) {
    return 0;
  }

  ctx = BN_CTX_new();
  field = bn_from_hex(BN254_FIELD);
  if (ctx == NULL || field == NULL) {
    goto cleanup;
  }
  if (!poseidon_generate_constants(&constants, &const_count, &params, field, ctx) ||
      !poseidon_generate_mds(&mds, params.t, field, ctx)) {
    goto cleanup;
  }

  state = (BIGNUM **)calloc(params.t, sizeof(BIGNUM *));
  next_state = (BIGNUM **)calloc(params.t, sizeof(BIGNUM *));
  if (state == NULL || next_state == NULL) {
    goto cleanup;
  }
  for (i = 0; i < params.t; i++) {
    state[i] = BN_new();
    next_state[i] = BN_new();
    if (state[i] == NULL || next_state[i] == NULL) {
      goto cleanup;
    }
    if (i == 0) {
      BN_zero(state[i]);
    } else if (BN_copy(state[i], inputs[i - 1]) == NULL) {
      goto cleanup;
    }
  }

  rounds = params.rf + params.rp;
  for (r = 0; r < rounds; r++) {
    for (i = 0; i < params.t; i++) {
      if (!BN_mod_add(state[i], state[i], constants[r * params.t + i], field, ctx)) {
        goto cleanup;
      }
    }
    if (r < (params.rf / 2) || r >= (params.rf / 2) + params.rp) {
      for (i = 0; i < params.t; i++) {
        if (!bn_mod_exp5(state[i], state[i], field, ctx)) {
          goto cleanup;
        }
      }
    } else {
      if (!bn_mod_exp5(state[0], state[0], field, ctx)) {
        goto cleanup;
      }
    }
    for (i = 0; i < params.t; i++) {
      BN_zero(next_state[i]);
      for (j = 0; j < params.t; j++) {
        BIGNUM *term = BN_new();
        if (term == NULL) {
          goto cleanup;
        }
        if (!BN_mod_mul(term, mds[i * params.t + j], state[j], field, ctx) ||
            !BN_mod_add(next_state[i], next_state[i], term, field, ctx)) {
          BN_free(term);
          goto cleanup;
        }
        BN_free(term);
      }
    }
    for (i = 0; i < params.t; i++) {
      if (BN_copy(state[i], next_state[i]) == NULL) {
        goto cleanup;
      }
    }
  }

  *out = BN_dup(state[1]);
  ok = (*out != NULL);

cleanup:
  if (constants != NULL) {
    for (i = 0; i < const_count; i++) {
      BN_free(constants[i]);
    }
    free(constants);
  }
  if (mds != NULL) {
    for (i = 0; i < params.t * params.t; i++) {
      BN_free(mds[i]);
    }
    free(mds);
  }
  if (state != NULL) {
    for (i = 0; i < params.t; i++) {
      BN_free(state[i]);
    }
    free(state);
  }
  if (next_state != NULL) {
    for (i = 0; i < params.t; i++) {
      BN_free(next_state[i]);
    }
    free(next_state);
  }
  BN_free(field);
  BN_CTX_free(ctx);
  return ok;
}

static int nullifying_key_from_viewing_private(const uint8_t viewing_private[32], BIGNUM **out) {
  BIGNUM *input = BN_bin2bn(viewing_private, 32, NULL);
  BIGNUM *inputs[1];
  int ok;
  if (input == NULL) {
    return 0;
  }
  inputs[0] = input;
  ok = poseidon_hash_bn(out, inputs, 1);
  BN_free(input);
  return ok;
}

static int master_public_key_from_components(const BIGNUM *pub_x, const BIGNUM *pub_y, const BIGNUM *nullifying_key, BIGNUM **out) {
  BIGNUM *inputs[3];
  inputs[0] = (BIGNUM *)pub_x;
  inputs[1] = (BIGNUM *)pub_y;
  inputs[2] = (BIGNUM *)nullifying_key;
  return poseidon_hash_bn(out, inputs, 3);
}

static uint32_t bech32_polymod(const uint8_t *values, size_t count) {
  static const uint32_t gen[5] = {
    0x3b6a57b2U, 0x26508e6dU, 0x1ea119faU, 0x3d4233ddU, 0x2a1462b3U,
  };
  uint32_t chk = 1;
  size_t i;
  size_t j;
  for (i = 0; i < count; i++) {
    uint8_t top = (uint8_t)(chk >> 25);
    chk = (chk & 0x1ffffffU) << 5 ^ values[i];
    for (j = 0; j < 5; j++) {
      if ((top >> j) & 1U) {
        chk ^= gen[j];
      }
    }
  }
  return chk;
}

static size_t bech32_hrp_expand(const char *hrp, uint8_t *out) {
  size_t i;
  size_t len = strlen(hrp);
  for (i = 0; i < len; i++) {
    out[i] = (uint8_t)(hrp[i] >> 5);
  }
  out[len] = 0;
  for (i = 0; i < len; i++) {
    out[len + 1 + i] = (uint8_t)(hrp[i] & 31);
  }
  return len * 2 + 1;
}

static int convert_bits(uint8_t *out, size_t *out_len, int outbits, const uint8_t *in, size_t in_len, int inbits, int pad) {
  uint32_t acc = 0;
  int bits = 0;
  size_t j = 0;
  uint32_t maxv = (1U << outbits) - 1U;
  size_t i;
  for (i = 0; i < in_len; i++) {
    if ((in[i] >> inbits) != 0) {
      return 0;
    }
    acc = (acc << inbits) | in[i];
    bits += inbits;
    while (bits >= outbits) {
      bits -= outbits;
      out[j++] = (uint8_t)((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits) {
      out[j++] = (uint8_t)((acc << (outbits - bits)) & maxv);
    }
  } else if (bits >= inbits || ((acc << (outbits - bits)) & maxv)) {
    return 0;
  }
  *out_len = j;
  return 1;
}

static int bech32m_encode(const char *hrp, const uint8_t *data, size_t data_len, char *out, size_t out_len) {
  static const char charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  uint8_t values[256];
  uint8_t expanded[256];
  uint8_t five_bit[256];
  uint8_t checksum_input[512];
  size_t expanded_len;
  size_t five_len = 0;
  size_t checksum_len;
  uint32_t polymod;
  size_t i;
  size_t pos = 0;

  if (!convert_bits(five_bit, &five_len, 5, data, data_len, 8, 1)) {
    return 0;
  }
  expanded_len = bech32_hrp_expand(hrp, expanded);
  memcpy(checksum_input, expanded, expanded_len);
  memcpy(checksum_input + expanded_len, five_bit, five_len);
  memset(checksum_input + expanded_len + five_len, 0, 6);
  checksum_len = expanded_len + five_len + 6;
  polymod = bech32_polymod(checksum_input, checksum_len) ^ 0x2bc830a3U;

  if (strlen(hrp) + 1 + five_len + 6 + 1 > out_len) {
    return 0;
  }
  memcpy(out, hrp, strlen(hrp));
  pos += strlen(hrp);
  out[pos++] = '1';
  for (i = 0; i < five_len; i++) {
    out[pos++] = charset[five_bit[i]];
  }
  for (i = 0; i < 6; i++) {
    uint8_t v = (uint8_t)((polymod >> (5 * (5 - i))) & 31U);
    out[pos++] = charset[v];
  }
  out[pos] = '\0';
  (void)values;
  return 1;
}

static int encode_address(
  const BIGNUM *spending_public_key_x,
  const BIGNUM *spending_public_key_y,
  const uint8_t viewing_public_key[32],
  int use_chain,
  uint8_t chain_type,
  uint64_t chain_id,
  char out[RAILGUN_ADDRESS_BUF]
) {
  uint8_t payload[73];
  uint8_t network_id[8];
  size_t i;

  payload[0] = 0x01;
  if (!bn_to_fixed_le(spending_public_key_y, payload + 1, 32)) {
    return 0;
  }
  payload[32] |= (uint8_t)((BN_is_odd(spending_public_key_x) ? 1 : 0) << 7);
  if (use_chain) {
    network_id[0] = chain_type;
    for (i = 0; i < 7; i++) {
      network_id[1 + i] = (uint8_t)(chain_id >> (8 * (6 - i)));
    }
  } else {
    memset(network_id, 0xff, sizeof(network_id));
  }
  for (i = 0; i < 7; i++) {
    network_id[i] ^= (uint8_t)"railgun"[i];
  }
  memcpy(payload + 33, network_id, 8);
  memcpy(payload + 41, viewing_public_key, 32);
  return bech32m_encode("0zk", payload, sizeof(payload), out, RAILGUN_ADDRESS_BUF);
}

int railgun_kohaku_account_from_mnemonic(
  const char *mnemonic,
  const char *passphrase,
  uint32_t index,
  int use_chain,
  uint8_t chain_type,
  uint64_t chain_id,
  railgun_kohaku_account_t *out,
  char error[RAILGUN_ERROR_BUF]
) {
  static const uint32_t spending_prefix[] = { 44, 1984, 0, 0 };
  static const uint32_t viewing_prefix[] = { 420, 1984, 0, 0 };
  uint8_t seed[64];
  uint8_t chain_code[32];
  uint32_t spending_path[5];
  uint32_t viewing_path[5];
  BIGNUM *spend_x = NULL;
  BIGNUM *spend_y = NULL;
  BIGNUM *nullifying = NULL;
  BIGNUM *master = NULL;
  int ok = 0;

  if (out == NULL) {
    set_error(error, "output account is required");
    return 0;
  }
  memset(out, 0, sizeof(*out));

  if (!railgun_kohaku_seed_from_mnemonic(mnemonic, passphrase, seed, error)) {
    return 0;
  }

  memcpy(spending_path, spending_prefix, sizeof(spending_prefix));
  memcpy(viewing_path, viewing_prefix, sizeof(viewing_prefix));
  spending_path[4] = index;
  viewing_path[4] = index;

  if (!derive_path_hardened(seed, spending_path, ARRAY_LEN(spending_path), out->spending_private_key, chain_code) ||
      !derive_path_ed25519_hardened(seed, viewing_path, ARRAY_LEN(viewing_path), out->viewing_private_key, chain_code)) {
    set_error(error, "BIP32 hardened derivation failed");
    goto cleanup;
  }
  if (!ed25519_public_from_seed(out->viewing_private_key, out->viewing_public_key)) {
    set_error(error, "Ed25519 public key derivation failed");
    goto cleanup;
  }
  if (!derive_spending_public_key(out->spending_private_key, &spend_x, &spend_y)) {
    set_error(error, "BabyJub spending public key derivation failed");
    goto cleanup;
  }
  if (!nullifying_key_from_viewing_private(out->viewing_private_key, &nullifying)) {
    set_error(error, "Poseidon nullifying key derivation failed");
    goto cleanup;
  }
  if (!master_public_key_from_components(spend_x, spend_y, nullifying, &master)) {
    set_error(error, "Poseidon master public key derivation failed");
    goto cleanup;
  }
  if (!bn_to_hex_dec(spend_x, out->spending_public_key_x, sizeof(out->spending_public_key_x)) ||
      !bn_to_hex_dec(spend_y, out->spending_public_key_y, sizeof(out->spending_public_key_y)) ||
      !bn_to_hex_dec(nullifying, out->nullifying_key, sizeof(out->nullifying_key)) ||
      !bn_to_hex_dec(master, out->master_public_key, sizeof(out->master_public_key))) {
    set_error(error, "decimal encoding failed");
    goto cleanup;
  }
  if (!encode_address(spend_x, spend_y, out->viewing_public_key, use_chain, chain_type, chain_id, out->address)) {
    set_error(error, "bech32m address encoding failed");
    goto cleanup;
  }
  if (error) {
    error[0] = '\0';
  }
  ok = 1;

cleanup:
  BN_free(spend_x);
  BN_free(spend_y);
  BN_free(nullifying);
  BN_free(master);
  OPENSSL_cleanse(seed, sizeof(seed));
  OPENSSL_cleanse(chain_code, sizeof(chain_code));
  return ok;
}
