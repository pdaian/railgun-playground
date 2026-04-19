#include "railgun_kohaku.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void expect(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "test failure: %s\n", message);
    exit(1);
  }
}

static void test_bip39_seed_vector(void) {
  const char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const char *expected =
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
  uint8_t seed[64];
  char error[RAILGUN_ERROR_BUF];
  char hex[129];

  expect(railgun_kohaku_seed_from_mnemonic(mnemonic, "", seed, error), error);
  for (size_t i = 0; i < 64; i++) {
    static const char digits[] = "0123456789abcdef";
    hex[i * 2] = digits[(seed[i] >> 4) & 0x0f];
    hex[i * 2 + 1] = digits[seed[i] & 0x0f];
  }
  hex[128] = '\0';
  expect(strcmp(hex, expected) == 0, "BIP39 seed mismatch");
}

static void test_account_generation_vector(void) {
  const char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  railgun_kohaku_account_t account;
  char error[RAILGUN_ERROR_BUF];

  expect(
    railgun_kohaku_account_from_mnemonic(mnemonic, "", 0, 1, 0, 1, &account, error),
    error
  );
  expect(strcmp(account.spending_public_key_x,
    "16548822702708443419878063133038333842919840334635209844990292084507202452414") == 0,
    "unexpected spending public key x");
  expect(strcmp(account.spending_public_key_y,
    "9159079664695724745030286177321235634169121018180208666481119968100738639349") == 0,
    "unexpected spending public key y");
  expect(strcmp(account.nullifying_key,
    "12851290987139213207337144641703473045639924564445433872002502580024498348591") == 0,
    "unexpected nullifying key");
  expect(strcmp(account.master_public_key,
    "403622650532849257806236323871346611442799281025603069778845114161407521106") == 0,
    "unexpected master public key");
  expect(strcmp(account.address,
    "0zk1qyqwgufu9hde3ufx6k589q9f5tc7rg9tfr2urugfw3k2sngrvrc4yunpd9kxwatwqxqmvzdnuv5eytel5mqejd95d8u8qtsr4nl6kzt0pzccwxgwc6dgxgtm3uw") == 0,
    "unexpected 0zk address");
}

int main(void) {
  test_bip39_seed_vector();
  test_account_generation_vector();
  puts("ok");
  return 0;
}
