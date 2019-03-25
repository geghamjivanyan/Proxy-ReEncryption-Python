from . import utils
from .private_key import PrivateKey
from .public_key import PublicKey
from .key_pair import KeyPair
from .capsule import Capsule
from .re_key import ReEncryptionKey


#
class Proxy(object):

    def __init__(self) -> None:
        pass

    @staticmethod
    def generate_key_pair() -> 'KeyPair':
        return KeyPair.generate_key_pair()

    @staticmethod
    def private_key_from_bytes(data: bytes) -> 'PrivateKey':
        """
        """
        return PrivateKey.from_bytes(data)

    @staticmethod
    def public_key_from_bytes(data: bytes) -> 'PublicKey':
        """
        """
        return PublicKey.from_bytes(data)

    @staticmethod
    def re_encryption_key_from_bytes(data: bytes) -> 'ReEncryptionKey':
        """
        """
        return ReEncryptionKey.from_bytes(data)

    @staticmethod
    def capsule_from_bytes(data: bytes) -> 'Capsule':
        """
        """
        return Capsule.from_bytes(data)

    @staticmethod
    def encapsulate(public_key):

        # generating 2 random key pairs

        kp_1 = Proxy.generate_key_pair()
        kp_2 = Proxy.generate_key_pair()

        # getting random private keys out of generated KeyPairs
        sk_1 = kp_1.get_private_key().value
        sk_2 = kp_2.get_private_key().value

        # getting random public key grop elements out of generated KeyPairs
        pk_1 = kp_1.get_public_key().get_group_element()
        pk_2 = kp_2.get_public_key().get_group_element()

        # concat public key group elements
        tmp_hash = [pk_1, pk_2]
        list_hash = utils.hash_to_scalar(tmp_hash)

        # Calculating part S from BN hashing -> sk_1 + sk_2 * list_hash
        part_S = sk_1 + sk_2 * list_hash

        # Making symmetric key

        # getting main public key group element
        pk_ge = public_key.get_group_element()

        # pk_ge * (sk1 + sk2)
        ge_symmetric = pk_ge * (sk_1 + sk_2)
        symmetric_key = utils.sha256(ge_symmetric)

        # return capsule
        capsule = Capsule(pk_1, pk_2, part_S)

        return capsule, symmetric_key

    @staticmethod
    def _decapsulate_original(capsule, private_key) -> str:
        # get private key value
        sk = private_key.value
        # capsule.E + capsule.V
        s = capsule.get_E() + capsule.get_V()

        # get symmetric key -> s * sk = (capsule.E + capsule.V) * sk
        ge_symmetric = s * sk
        symmetric_key = utils.sha256(ge_symmetric)
        return symmetric_key

    @staticmethod
    def generate_re_encryption_key(private_key: PrivateKey, public_key: PublicKey) -> 'ReEncryptionKey':
        # generate random key pair
        kp = Proxy.generate_key_pair()

        # get random key values
        tmp_sk = kp.get_private_key().value
        tmp_pk = kp.get_public_key().get_group_element()

        # get public key group element
        pk = public_key.get_group_element()

        # concat main public key, tmp public key and pk * tmp_sk
        tmp_hash = [tmp_pk, pk, pk * tmp_sk]
        list_hash = utils.hash_to_scalar(tmp_hash)

        # get private key value
        sk = private_key.value

        rk = sk * (~list_hash)
        return ReEncryptionKey(rk, tmp_pk)

    @staticmethod
    def re_encrypt_capsule(capsule: Capsule, rk: ReEncryptionKey) -> 'Capsule':
        prime_E = capsule.get_E() * rk.get_re_key()
        prime_V = capsule.get_V() * rk.get_re_key()
        prime_S = capsule.get_S()

        return Capsule(prime_E, prime_V, prime_S, rk.get_internal_public_key(), True)

    @staticmethod
    def _decapsulate_re_encrypted(capsule: Capsule, private_key: PrivateKey) -> str:
        prime_XG = capsule.get_XG()
        prime_E = capsule.get_E()
        prime_V = capsule.get_V()

        # concat prime_XG, public key group_element and prime_XG * sk
        tmp_hash = [prime_XG, private_key.get_public_key().get_group_element(), prime_XG * private_key.value]
        list_hash = utils.hash_to_scalar(tmp_hash)

        # (capsule.E + capsule.V) * list_hash
        tmp_ge = (prime_E + prime_V) * list_hash

        symmetric_key = utils.sha256(tmp_ge)
        return symmetric_key

    @staticmethod
    def decapsulate(capsule: Capsule, private_key: PrivateKey) -> 'str':
        if capsule.is_re_encrypted():
            return Proxy._decapsulate_re_encrypted(capsule, private_key)
        return Proxy._decapsulate_original(capsule, private_key)
