#ifndef RAILGUN_KOHAKU_H
#define RAILGUN_KOHAKU_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RAILGUN_HEX_32_LEN 64
#define RAILGUN_HEX_32_BUF 65
#define RAILGUN_BABYJUB_COORD_BUF 80
#define RAILGUN_ADDRESS_BUF 128
#define RAILGUN_STATUS_BUF 16
#define RAILGUN_TX_ID_BUF 65
#define RAILGUN_ERROR_BUF 256

typedef struct railgun_kohaku_account {
  uint8_t spending_private_key[32];
  uint8_t viewing_private_key[32];
  uint8_t viewing_public_key[32];
  char spending_public_key_x[RAILGUN_BABYJUB_COORD_BUF];
  char spending_public_key_y[RAILGUN_BABYJUB_COORD_BUF];
  char nullifying_key[RAILGUN_BABYJUB_COORD_BUF];
  char master_public_key[RAILGUN_BABYJUB_COORD_BUF];
  char address[RAILGUN_ADDRESS_BUF];
} railgun_kohaku_account_t;

typedef struct railgun_kohaku_ledger_entry {
  char address[RAILGUN_ADDRESS_BUF];
  uint64_t balance;
} railgun_kohaku_ledger_entry_t;

typedef struct railgun_kohaku_ledger {
  railgun_kohaku_ledger_entry_t *entries;
  size_t capacity;
  size_t count;
} railgun_kohaku_ledger_t;

typedef struct railgun_kohaku_balance_info {
  uint64_t balance;
  int is_active;
  char status[RAILGUN_STATUS_BUF];
} railgun_kohaku_balance_info_t;

typedef struct railgun_kohaku_transfer_receipt {
  char tx_id[RAILGUN_TX_ID_BUF];
  char from_address[RAILGUN_ADDRESS_BUF];
  char to_address[RAILGUN_ADDRESS_BUF];
  uint64_t amount;
  uint64_t sender_balance;
  uint64_t recipient_balance;
} railgun_kohaku_transfer_receipt_t;

int railgun_kohaku_seed_from_mnemonic(
  const char *mnemonic,
  const char *passphrase,
  uint8_t seed_out[64],
  char error[RAILGUN_ERROR_BUF]
);

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

int railgun_kohaku_ledger_init(
  railgun_kohaku_ledger_t *ledger,
  railgun_kohaku_ledger_entry_t *entries,
  size_t capacity,
  char error[RAILGUN_ERROR_BUF]
);

int railgun_kohaku_ledger_set_balance(
  railgun_kohaku_ledger_t *ledger,
  const char *address,
  uint64_t balance,
  char error[RAILGUN_ERROR_BUF]
);

int railgun_kohaku_check_account_balance(
  const railgun_kohaku_ledger_t *ledger,
  const char *address,
  railgun_kohaku_balance_info_t *out,
  char error[RAILGUN_ERROR_BUF]
);

int railgun_kohaku_send_funds(
  railgun_kohaku_ledger_t *ledger,
  const char *from_address,
  const char *to_address,
  uint64_t amount,
  railgun_kohaku_transfer_receipt_t *out,
  char error[RAILGUN_ERROR_BUF]
);

int railgun_kohaku_receive_funds(
  railgun_kohaku_ledger_t *ledger,
  const char *to_address,
  uint64_t amount,
  const char *source_address,
  railgun_kohaku_transfer_receipt_t *out,
  char error[RAILGUN_ERROR_BUF]
);

#ifdef __cplusplus
}
#endif

#endif
