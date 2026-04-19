import unittest

from railgun_kohaku import (
    RailgunKohakuLedger,
    account_from_mnemonic,
    seed_from_mnemonic,
)


MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about"
)


class RailgunKohakuTests(unittest.TestCase):
    def test_bip39_seed_vector(self) -> None:
        expected = (
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
            "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        )
        self.assertEqual(seed_from_mnemonic(MNEMONIC).hex(), expected)

    def test_bip39_seed_normalizes_unicode_inputs(self) -> None:
        self.assertEqual(
            seed_from_mnemonic("abandon", passphrase="pr\u00e9fixe"),
            seed_from_mnemonic("abandon", passphrase="pre\u0301fixe"),
        )
        self.assertEqual(
            seed_from_mnemonic("caf\u00e9"),
            seed_from_mnemonic("cafe\u0301"),
        )

    def test_account_generation_vector(self) -> None:
        account = account_from_mnemonic(
            MNEMONIC,
            index=0,
            use_chain=True,
            chain_type=0,
            chain_id=1,
        )
        self.assertEqual(
            account.spending_public_key_x,
            "16548822702708443419878063133038333842919840334635209844990292084507202452414",
        )
        self.assertEqual(
            account.spending_public_key_y,
            "9159079664695724745030286177321235634169121018180208666481119968100738639349",
        )
        self.assertEqual(
            account.nullifying_key,
            "12851290987139213207337144641703473045639924564445433872002502580024498348591",
        )
        self.assertEqual(
            account.master_public_key,
            "403622650532849257806236323871346611442799281025603069778845114161407521106",
        )
        self.assertEqual(
            account.address,
            "0zk1qyqwgufu9hde3ufx6k589q9f5tc7rg9tfr2urugfw3k2sngrvrc4yunpd9kxwatwqxqmvzdnuv5eytel5mqejd95d8u8qtsr4nl6kzt0pzccwxgwc6dgxgtm3uw",
        )

    def test_ledger_balance_send_and_receive(self) -> None:
        sender = account_from_mnemonic(MNEMONIC, index=0, use_chain=True, chain_type=0, chain_id=1)
        recipient = account_from_mnemonic(MNEMONIC, index=1, use_chain=True, chain_type=0, chain_id=1)
        ledger = RailgunKohakuLedger()

        inactive = ledger.check_account_balance(sender.address)
        self.assertEqual(inactive.balance, 0)
        self.assertFalse(inactive.is_active)
        self.assertEqual(inactive.status, "inactive")

        receive_receipt = ledger.receive_funds(sender, 50)
        self.assertEqual(receive_receipt.from_address, "external")
        self.assertEqual(receive_receipt.to_address, sender.address)
        self.assertEqual(receive_receipt.amount, 50)
        self.assertEqual(receive_receipt.sender_balance, 0)
        self.assertEqual(receive_receipt.recipient_balance, 50)
        self.assertEqual(len(receive_receipt.tx_id), 64)

        active = ledger.check_account_balance(sender.address)
        self.assertEqual(active.balance, 50)
        self.assertTrue(active.is_active)
        self.assertEqual(active.status, "active")

        send_receipt = ledger.send_funds(sender, recipient, 20)
        self.assertEqual(send_receipt.from_address, sender.address)
        self.assertEqual(send_receipt.to_address, recipient.address)
        self.assertEqual(send_receipt.amount, 20)
        self.assertEqual(send_receipt.sender_balance, 30)
        self.assertEqual(send_receipt.recipient_balance, 20)
        self.assertEqual(len(send_receipt.tx_id), 64)

        self.assertEqual(ledger.check_account_balance(sender.address).balance, 30)
        self.assertEqual(ledger.check_account_balance(recipient.address).balance, 20)


if __name__ == "__main__":
    unittest.main()
