#
from proxy_test import BaseTest

#
from binascii import hexlify as to_hex

#
from kmschain.private_key import PrivateKey
from kmschain.proxy import Proxy
from kmschain.public_key import PublicKey
from kmschain.re_key import ReEncryptionKey


class TestKeys(BaseTest):
    #
    def setUp(self):
        super(TestKeys, self).setUp()

    def test_private_key(self):
        """
        Private key test
        """

        print("\nPRIVATE KEY TEST\n")

        sk = PrivateKey.generate()

        sk_b = sk.to_bytes()
        self.assertEqual(len(sk_b), 32)

        sk_f = PrivateKey.from_bytes(sk_b)

        sk_f_b = sk_f.to_bytes()
        self.assertEqual(len(sk_f_b), 32)

        self.assertEqual(sk_b, sk_f_b)
        self.assertEqual(to_hex(sk_b), to_hex(sk_f_b))

    def test_public_key(self):
        """
        Public key test
        """

        print("\nPUBLIC KEY TEST\n")

        sk = PrivateKey.generate()
        pk = sk.get_public_key()

        pk_b = pk.to_bytes()
        self.assertEqual(len(pk_b), 65)

        pk_f = PublicKey.from_bytes(pk_b)

        pk_f_b = pk_f.to_bytes()
        self.assertEqual(len(pk_f_b), 65)

        self.assertEqual(pk_b, pk_f_b)
        self.assertEqual(to_hex(pk_b), to_hex(pk_f_b))

    def test_re_key(self):
        """
        Re Encryption key test
        """

        print("\nRE ENCRYPTION KEY TEST\n")

        sk_A = PrivateKey.generate()
        sk_B = PrivateKey.generate()

        pk_A = sk_A.get_public_key()
        pk_B = sk_B.get_public_key()

        # generate re-key from Alice to Bob
        rk_AB = Proxy.generate_re_encryption_key(sk_A, pk_B)

        rk_AB_b = rk_AB.to_bytes()
        self.assertEqual(len(rk_AB_b), 97)

        rk_AB_f = ReEncryptionKey.from_bytes(rk_AB_b)

        assert isinstance(rk_AB_f, ReEncryptionKey)

        rk_AB_f_b = rk_AB_f.to_bytes()
        self.assertEqual(len(rk_AB_f_b), 97)

        self.assertEqual(rk_AB_b, rk_AB_f_b)
        self.assertEqual(to_hex(rk_AB_b), to_hex(rk_AB_f_b))

        # generate re-key from Bob to Alice
        rk_BA = Proxy.generate_re_encryption_key(sk_B, pk_A)

        rk_BA_b = rk_BA.to_bytes()
        self.assertEqual(len(rk_BA_b), 97)

        rk_BA_f = ReEncryptionKey.from_bytes(rk_BA_b)
        assert isinstance(rk_BA_f, ReEncryptionKey)

        rk_BA_f_b = rk_BA_f.to_bytes()
        self.assertEqual(len(rk_BA_f_b), 97)

        self.assertEqual(rk_BA_b, rk_BA_f_b)
        self.assertEqual(to_hex(rk_BA_b), to_hex(rk_BA_f_b))
