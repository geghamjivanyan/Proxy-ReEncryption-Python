from typing import Optional, Union, cast

from . import config
from . import openssl_wrap as openssl
from .curve import Curve

from cryptography.hazmat.backends.openssl import backend


class Scalar(object):

    def __init__(self, scalar, curve: Optional[Curve] = None) -> None:

        curve = curve if curve is not None else config.default_curve()
        on_curve = openssl._bn_is_on_curve(scalar, curve)
        if not on_curve:
            raise ValueError("The provided SCALAR is not on the provided curve.")

        self.scalar = scalar
        self.curve = curve

    @classmethod
    def expected_bytes_length(cls, curve: Optional[Curve] = None) -> int:
        """
        """
        curve = curve if curve is not None else config.default_curve()
        return curve.group_order_size_in_bytes

    @classmethod
    def generate_random(cls, curve: Optional[Curve] = None) -> 'Scalar':
        """
        """
        curve = curve if curve is not None else config.default_curve()
        new_rand_bn = openssl._get_new_BN()
        rand_res = backend._lib.BN_rand_range(new_rand_bn, curve.order)
        backend.openssl_assert(rand_res == 1)

        if not openssl._bn_is_on_curve(new_rand_bn, curve):
            new_rand_bn = cls.generate_random(curve=curve)
            return new_rand_bn

        return cls(new_rand_bn, curve)

    @classmethod
    def from_bytes(cls, data: bytes, curve: Optional[Curve] = None) -> 'Scalar':
        """
        """
        curve = curve if curve is not None else config.default_curve()

        size = backend._lib.BN_num_bytes(curve.order)
        if len(data) != size:
            raise ValueError("Expected {} Bytes for Scalars".format(size))
        scalar = openssl._bytes_to_bn(data)
        return cls(scalar, curve)

    def to_bytes(self) -> bytes:
        """
        """
        size = backend._lib.BN_num_bytes(self.curve.order)
        return openssl._bn_to_bytes(self.scalar, size)

    def __int__(self) -> int:
        """
        Converts the Scalar to a Python int.
        """
        return backend._bn_to_int(self.scalar)

    def __mul__(self, other) -> 'Scalar':
        """
        """
        if type(other) != Scalar:
            return NotImplemented

        product = openssl._get_new_BN()
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_mod_mul(
                product, self.scalar, other.scalar, self.curve.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return Scalar(product, self.curve)

    def __add__(self, other: Union[int, 'Scalar']) -> 'Scalar':
        """
        """
        if type(other) == int:
            other = openssl._int_to_bn(other)
            other = Scalar(other, self.curve)

        other = cast('Scalar', other)

        op_sum = openssl._get_new_BN()
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_mod_add(
                op_sum, self.scalar, other.scalar, self.curve.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return Scalar(op_sum, self.curve)

    def __sub__(self, other: Union[int, 'Scalar']) -> 'Scalar':
        """
        """
        if type(other) == int:
            other = openssl._int_to_bn(other)
            other = Scalar(other, self.curve)

        other = cast('Scalar', other)  # This is just for mypy

        diff = openssl._get_new_BN()
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_mod_sub(
                diff, self.scalar, other.scalar, self.curve.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return Scalar(diff, self.curve)

    def __invert__(self) -> 'Scalar':
        """
        """
        with backend._tmp_bn_ctx() as bn_ctx:
            inv = backend._lib.BN_mod_inverse(
                backend._ffi.NULL, self.scalar, self.curve.order, bn_ctx
            )
            backend.openssl_assert(inv != backend._ffi.NULL)
            inv = backend._ffi.gc(inv, backend._lib.BN_clear_free)

        return Scalar(inv, self.curve)

    def __mod__(self, other: Union[int, 'Scalar']) -> 'Scalar':
        """
        """
        if type(other) == int:
            other = openssl._int_to_bn(other)
            other = Scalar(other, self.curve)

        other = cast('Scalar', other)  # This is just for mypy

        rem = openssl._get_new_BN()

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_nnmod(
                rem, self.bignum, other.bignum, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return Scalar(rem, self.curve)

    def __truediv__(self, other: 'Scalar') -> 'Scalar':
        """
        """
        product = openssl._get_new_BN()
        with backend._tmp_bn_ctx() as bn_ctx:
            inv_other = backend._lib.BN_mod_inverse(
                backend._ffi.NULL, other.scalar, self.curve.order, bn_ctx
            )
            backend.openssl_assert(inv_other != backend._ffi.NULL)
            inv_other = backend._ffi.gc(inv_other, backend._lib.BN_clear_free)

            res = backend._lib.BN_mod_mul(
                product, self.scalar, inv_other, self.curve.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return Scalar(product, self.curve)
