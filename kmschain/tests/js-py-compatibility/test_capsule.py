#
from proxy_test import BaseTest

#
from kmschain.proxy import Proxy


class TestCapsule(BaseTest):
    #
    def setUp(self):
        super(TestCapsule, self).setUp()

    def test_time(self):
        """
        Time test
        """
        import time
        print("\nTime Testing\n")

        start_time = time.time()
        kp_A = Proxy.generate_key_pair()
        end_time = time.time()
        print("\nGenerate Key pair - {}\n".format(end_time - start_time))

        sk_A = kp_A.get_private_key()
        pk_A = kp_A.get_public_key()

        kp_B = Proxy.generate_key_pair()
        sk_B = kp_B.get_private_key()
        pk_B = kp_B.get_public_key()

        start_time = time.time()
        capsule, sym_key_A = Proxy.encapsulate(pk_A)
        end_time = time.time()
        print("\nEncapsulate - {}\n".format(end_time - start_time))

        start_time = time.time()
        Proxy.decapsulate(capsule, sk_A)
        end_time = time.time()
        print("\nDecapsulate Original - {}\n".format(end_time - start_time))

        start_time = time.time()
        rk_AB = Proxy.generate_re_encryption_key(sk_A, pk_B)
        end_time = time.time()
        print("\nGenerate ReEncryptionKey - {}\n".format(end_time - start_time))

        start_time = time.time()
        re_capsule = Proxy.re_encrypt_capsule(capsule, rk_AB)
        end_time = time.time()
        print("\nReEncrypt Capsule - {}\n".format(end_time - start_time))

        start_time = time.time()
        Proxy.decapsulate(re_capsule, sk_B)
        end_time = time.time()
        print("\nDecapsulate ReEncrypted - {}\n".format(end_time - start_time))
