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
    "1850833569702457231862605360486573998469253365125087039228198490653943843553") == 0,
    "unexpected nullifying key");
  expect(strcmp(account.master_public_key,
    "5674360650772448173541023358492207952032557933582476282401050051868333884155") == 0,
    "unexpected master public key");
  expect(strcmp(account.address,
    "0zk1q8662zeu25nuzud9542rlcjj3arj69uwau6jlqth6r076386mgl3gunpd9kxwatwqyj9vw533xyqae63ju7gqx4vwx9ggx6rks7ypv6uawhxe8k92uzj2f8edwn") == 0,
    "unexpected 0zk address");
}

static void test_ledger_balance_send_and_receive(void) {
  const char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  railgun_kohaku_account_t sender;
  railgun_kohaku_account_t recipient;
  railgun_kohaku_ledger_entry_t entries[4];
  railgun_kohaku_ledger_t ledger;
  railgun_kohaku_balance_info_t balance;
  railgun_kohaku_transfer_receipt_t receipt;
  char error[RAILGUN_ERROR_BUF];

  expect(railgun_kohaku_account_from_mnemonic(mnemonic, "", 0, 1, 0, 1, &sender, error), error);
  expect(railgun_kohaku_account_from_mnemonic(mnemonic, "", 1, 1, 0, 1, &recipient, error), error);
  expect(railgun_kohaku_ledger_init(&ledger, entries, 4, error), error);

  expect(railgun_kohaku_check_account_balance(&ledger, sender.address, &balance, error), error);
  expect(balance.balance == 0, "unexpected initial balance");
  expect(balance.is_active == 0, "initial account should be inactive");
  expect(strcmp(balance.status, "inactive") == 0, "unexpected initial status");

  expect(railgun_kohaku_receive_funds(&ledger, sender.address, 50, NULL, &receipt, error), error);
  expect(strcmp(receipt.from_address, "external") == 0, "unexpected receive source");
  expect(strcmp(receipt.to_address, sender.address) == 0, "unexpected receive destination");
  expect(receipt.amount == 50, "unexpected receive amount");
  expect(receipt.sender_balance == 0, "unexpected external sender balance");
  expect(receipt.recipient_balance == 50, "unexpected recipient balance after receive");
  expect(strlen(receipt.tx_id) == 64, "unexpected receive tx id length");

  expect(railgun_kohaku_check_account_balance(&ledger, sender.address, &balance, error), error);
  expect(balance.balance == 50, "unexpected balance after receive");
  expect(balance.is_active == 1, "account should be active after receive");
  expect(strcmp(balance.status, "active") == 0, "unexpected active status");

  expect(railgun_kohaku_send_funds(&ledger, sender.address, recipient.address, 20, &receipt, error), error);
  expect(strcmp(receipt.from_address, sender.address) == 0, "unexpected send source");
  expect(strcmp(receipt.to_address, recipient.address) == 0, "unexpected send destination");
  expect(receipt.amount == 20, "unexpected send amount");
  expect(receipt.sender_balance == 30, "unexpected sender balance after send");
  expect(receipt.recipient_balance == 20, "unexpected recipient balance after send");
  expect(strlen(receipt.tx_id) == 64, "unexpected send tx id length");

  expect(railgun_kohaku_check_account_balance(&ledger, sender.address, &balance, error), error);
  expect(balance.balance == 30, "unexpected sender final balance");
  expect(railgun_kohaku_check_account_balance(&ledger, recipient.address, &balance, error), error);
  expect(balance.balance == 20, "unexpected recipient final balance");
}

int main(void) {
  test_bip39_seed_vector();
  test_account_generation_vector();
  test_ledger_balance_send_and_receive();
  puts("ok");
  return 0;
}
