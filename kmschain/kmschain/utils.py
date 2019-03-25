"""
"""
from binascii import hexlify as to_hex


from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes

from . import openssl_wrap as openssl
from .scalar import Scalar
from .curve import SECP256K1


def sha256(point):

    hash_obj = hashes.Hash(hashes.SHA256(), backend=backend)

    try:
        point_bytes = to_hex(point.to_bytes())
    except AttributeError:
        raise TypeError("Input with type {} not accepted".format(type(point)))
    hash_obj.update(point_bytes)

    hash_digest = openssl._bytes_to_bn(hash_obj.finalize())

    return Scalar(hash_digest)


def hash_to_scalar(points) -> Scalar:

    hash_obj = hashes.Hash(hashes.SHA256(), backend=backend)
    for point in points:
        try:
            point_bytes = to_hex(point.to_bytes())
        except AttributeError:
                raise TypeError("Input with type {} not accepted".format(type(point)))
        hash_obj.update(point_bytes)

    hash_digest = openssl._bytes_to_bn(hash_obj.finalize())

    one = backend._lib.BN_value_one()

    order_minus_1 = openssl._get_new_BN()
    res = backend._lib.BN_sub(order_minus_1, SECP256K1.order, one)
    backend.openssl_assert(res == 1)

    bignum = openssl._get_new_BN()
    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.BN_mod(bignum, hash_digest, order_minus_1, bn_ctx)
        backend.openssl_assert(res == 1)

    res = backend._lib.BN_add(bignum, bignum, one)
    backend.openssl_assert(res == 1)

    return Scalar(bignum)
