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

#ifdef __cplusplus
}
#endif

#endif
