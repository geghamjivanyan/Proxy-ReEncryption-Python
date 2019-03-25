#
from proxy_test import BaseTest


#
from binascii import hexlify as to_hex, unhexlify as from_hex

#
from kmschain.private_key import PrivateKey
from kmschain.proxy import Proxy
from kmschain.public_key import PublicKey
from kmschain.capsule import Capsule


class TestCompatibility(BaseTest):

    #
    def setUp(self):
        super(TestCompatibility, self).setUp()

    def test_generate_alice_keys(self):
        kp = Proxy.generate_key_pair()
        sk = kp.get_private_key()
        f = open("decapsulate_re_encrypted/private.txt", "w+")
        f.write(to_hex(sk.to_bytes()).decode('utf-8') + '\n')
        f.close()

        pk = kp.get_public_key()
        f = open("decapsulate_re_encrypted/public.txt", "w+")
        f.write(to_hex(pk.to_bytes()).decode('utf-8') + '\n')
        f.close()

        capsule, sym_key = Proxy.encapsulate(pk)
        f = open("decapsulate_re_encrypted/symmetric_key.txt", "w+")
        f.write(to_hex(sym_key.to_bytes()).decode('utf-8') + '\n')
        f.close()

        f = open("decapsulate_re_encrypted/capsule.txt", "w+")
        f.write(to_hex(capsule.to_bytes()).decode('utf-8') + '\n')

        f.close()

    def test_generate_rk_ab(self):

        f = open("decapsulate_re_encrypted/private.txt", "r")
        sk_hex = f.read()[:-1]
        f.close()
        sk_A = PrivateKey.from_bytes(from_hex(sk_hex))

        f = open("/home/gegham/Desktop/sky-sdk/js-sdk-skycryptor/js_src/files/keys/public.txt", "r")
        pk_hex = f.read()[:-1]
        f.close()
        pk_B = PublicKey.from_bytes(from_hex(pk_hex))

        print("PK_B - {}\n".format(to_hex(pk_B.to_bytes())))

        f = open("/home/gegham/Desktop/sky-sdk/js-sdk-skycryptor/js_src/files/keys/private.txt", "r")
        sk_hex_b = f.read()[:-1]
        print("SK_B - ", sk_hex_b + "\n")
        f.close()
        sk_B = PrivateKey.from_bytes(from_hex(sk_hex_b))

        rk_AB = Proxy.generate_re_encryption_key(sk_A, pk_B)
        f = open("decapsulate_re_encrypted/rk_AB.txt", "w+")
        f.write(to_hex(rk_AB.to_bytes()).decode('utf-8') + '\n')
        f.close()

        f = open("decapsulate_re_encrypted/capsule.txt", "r")
        capsule_hex = f.read()[:-1]
        f.close()
        capsule = Capsule.from_bytes(from_hex(capsule_hex))

        re_capsule = Proxy.re_encrypt_capsule(capsule, rk_AB)

        f = open("decapsulate_re_encrypted/re_capsule.txt", "w+")
        f.write(to_hex(re_capsule.to_bytes()).decode('utf-8') + '\n')
        f.close()

        f = open("decapsulate_re_encrypted/re_capsule.txt", "r")
        re_capsule_hex = f.read()[:-1]
        f.close()
        re_cap = Capsule.from_bytes(from_hex(re_capsule_hex))
        sym_key = Proxy.decapsulate(re_cap, sk_B)

        print("SYM KEY - " + str(to_hex(sym_key.to_bytes())) + "\n")
