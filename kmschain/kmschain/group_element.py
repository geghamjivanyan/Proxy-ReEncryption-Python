
from typing import Optional

from cryptography.hazmat.backends.openssl import backend

from . import openssl_wrap as openssl
from .config import default_curve
from .curve import Curve
from .scalar import Scalar


class GroupElement(object):
    """
    """

    def __init__(self, ec_point, curve: Curve) -> None:
        self.ec_point = ec_point
        self.curve = curve

    @classmethod
    def expected_bytes_length(cls, curve: Optional[Curve] = None,
                              is_compressed: bool = False):
        """
        """
        curve = curve if curve is not None else default_curve()

        coord_size = curve.field_order_size_in_bytes

        if is_compressed:
            return 1 + coord_size
        else:
            return 1 + 2 * coord_size

    @classmethod
    def generate_random(cls, curve: Optional[Curve] = None) -> 'GroupElement':
        """
        Returns a GroupElement object with a cryptographically secure EC_POINT based
        on the provided curve.
        """
        curve = curve if curve is not None else default_curve()

        rand_point = openssl._get_new_EC_POINT(curve)
        rand_bn = Scalar.generate_random(curve).scalar

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_mul(
                curve.ec_group, rand_point, backend._ffi.NULL, curve.generator,
                rand_bn, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return cls(rand_point, curve)

    @classmethod
    def from_bytes(cls, data: bytes, curve: Optional[Curve] = None) -> 'GroupElement':
        """
        """
        curve = curve if curve is not None else default_curve()

        point = openssl._get_new_EC_POINT(curve)
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_oct2point(
                curve.ec_group, point, data, len(data), bn_ctx)
            backend.openssl_assert(res == 1)

        return cls(point, curve)

    def to_bytes(self, is_compressed: bool=False) -> bytes:
        """
        """
        length = self.expected_bytes_length(self.curve, is_compressed)

        if is_compressed:
            point_conversion_form = backend._lib.POINT_CONVERSION_COMPRESSED
        else:
            point_conversion_form = backend._lib.POINT_CONVERSION_UNCOMPRESSED

        bin_ptr = backend._ffi.new("unsigned char[]", length)
        with backend._tmp_bn_ctx() as bn_ctx:
            bin_len = backend._lib.EC_POINT_point2oct(
                self.curve.ec_group, self.ec_point, point_conversion_form,
                bin_ptr, length, bn_ctx
            )
            backend.openssl_assert(bin_len != 0)

        return bytes(backend._ffi.buffer(bin_ptr, bin_len)[:])

    @classmethod
    def get_generator_from_curve(cls, curve: Optional[Curve] = None) -> 'GroupElement':
        """
        """
        curve = curve if curve is not None else default_curve()
        return cls(curve.generator, curve)

    def __eq__(self, other):
        """
        """
        with backend._tmp_bn_ctx() as bn_ctx:
            is_equal = backend._lib.EC_POINT_cmp(
                self.curve.ec_group, self.ec_point, other.ec_point, bn_ctx
            )
            backend.openssl_assert(is_equal != -1)

        # 1 is not-equal, 0 is equal, -1 is error
        return not bool(is_equal)

    def __mul__(self, other: Scalar) -> 'GroupElement':
        """
        """
        # TODO: Check that both points use the same curve.
        prod = openssl._get_new_EC_POINT(self.curve)
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_mul(
                self.curve.ec_group, prod, backend._ffi.NULL,
                self.ec_point, other.scalar, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return GroupElement(prod, self.curve)

    __rmul__ = __mul__

    def __add__(self, other) -> 'GroupElement':
        """
        """
        op_sum = openssl._get_new_EC_POINT(self.curve)
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_add(
                self.curve.ec_group, op_sum, self.ec_point, other.ec_point, bn_ctx
            )
            backend.openssl_assert(res == 1)
        return GroupElement(op_sum, self.curve)

    def __bytes__(self) -> bytes:
        return self.to_bytes()
