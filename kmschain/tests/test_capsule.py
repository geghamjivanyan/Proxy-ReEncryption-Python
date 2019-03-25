#
from proxy_test import BaseTest

#
from binascii import hexlify as to_hex

#
from kmschain.private_key import PrivateKey
from kmschain.scalar import Scalar
from kmschain.proxy import Proxy
from kmschain.capsule import Capsule


class TestCapsule(BaseTest):
    #
    def setUp(self):
        super(TestCapsule, self).setUp()

    def test_original_capsule(self):
        """
        Original Capsule test
        """

        print("\nORIGINAL CAPSULE TEST\n")

        sk = PrivateKey.generate()
        pk = sk.get_public_key()

        capsule, _ = Proxy.encapsulate(pk)

        assert isinstance(capsule, Capsule)

        capsule_b = capsule.to_bytes()
        self.assertEqual(capsule.is_re_encrypted(), False)
        self.assertEqual(len(capsule_b), 162)

        capsule_f = Capsule.from_bytes(capsule_b)
        assert isinstance(capsule_f, Capsule)

        capsule_f_b = capsule_f.to_bytes()
        self.assertEqual(len(capsule_f_b), 162)

        self.assertEqual(capsule_b, capsule_f_b)
        self.assertEqual(to_hex(capsule_b), to_hex(capsule_f_b))

    def test_decapsulate_original_capsule(self):
        """
        Original Capsule decapsulate test
        """

        print("\nDECAPSULATE ORIGINAL CAPSULE TEST\n")

        kp = Proxy.generate_key_pair()
        sk = kp.get_private_key()

        pk = kp.get_public_key()
        capsule, sym_key = Proxy.encapsulate(pk)
        assert isinstance(capsule, Capsule)
        assert isinstance(sym_key, Scalar)

        dec_sym_key = Proxy.decapsulate(capsule, sk)

        assert isinstance(dec_sym_key, Scalar)
        self.assertEqual(sym_key.to_bytes(), dec_sym_key.to_bytes())
        self.assertEqual(to_hex(sym_key.to_bytes()), to_hex(dec_sym_key.to_bytes()))

    def test_decapsulate_re_encrypted_capsule(self):
        """
        Re Encrypted Capsule decapsulate test
        """

        print("\nDECAPSULATE RE ENCRYPTED CAPSULE TEST\n")

        kp_A = Proxy.generate_key_pair()
        sk_A = kp_A.get_private_key()
        pk_A = kp_A.get_public_key()

        kp_B = Proxy.generate_key_pair()
        sk_B = kp_B.get_private_key()
        pk_B = kp_B.get_public_key()

        capsule, sym_key_A = Proxy.encapsulate(pk_A)
        assert isinstance(capsule, Capsule)
        assert isinstance(sym_key_A, Scalar)

        rk_AB = Proxy.generate_re_encryption_key(sk_A, pk_B)

        re_capsule = Proxy.re_encrypt_capsule(capsule, rk_AB)
        assert isinstance(re_capsule, Capsule)

        self.assertEqual(re_capsule.is_re_encrypted(), True)

        re_capsule_b = re_capsule.to_bytes()
        self.assertEqual(len(re_capsule_b), 227)

        re_capsule_f = Capsule.from_bytes(re_capsule_b)
        assert isinstance(re_capsule_f, Capsule)

        re_capsule_f_b = re_capsule_f.to_bytes()
        self.assertEqual(re_capsule_b, re_capsule_f_b)

        sym_key_B = Proxy.decapsulate(re_capsule, sk_B)
        assert isinstance(sym_key_B, Scalar)

        self.assertEqual(sym_key_A.to_bytes(), sym_key_B.to_bytes())
