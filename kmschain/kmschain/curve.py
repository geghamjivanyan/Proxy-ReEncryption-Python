"""
"""

from cryptography.hazmat.backends import default_backend

from . import openssl_wrap as openssl


class Curve:
    """
    """

    _supported_curves = {
        714: 'secp256k1',
    }

    def __init__(self, curve_id: int) -> None:
        """
        """

        try:
            self.__curve_name = self._supported_curves[curve_id]
        except KeyError:
            raise NotImplementedError("Curve ID {} is not supported.".format(curve_id))

        # set only once
        self.__curve_id = curve_id
        self.__ec_group = openssl._get_ec_group_by_curve_id(self.__curve_id)
        self.__order = openssl._get_ec_order_by_group(self.ec_group)
        self.__generator = openssl._get_ec_generator_by_group(self.ec_group)

        # Init cache
        self.__field_order_size_in_bytes = 0
        self.__group_order_size_in_bytes = 0

    @classmethod
    def from_name(cls, name: str) -> 'Curve':
        """

        """

        name = name.casefold()  # normalize

        for supported_id, supported_name in cls._supported_curves.items():
            if name == supported_name:
                instance = cls(curve_id=supported_id)
                break
        else:
            message = "{} is not supported curve name.".format(name)
            raise NotImplementedError(message)

        return instance

    def __eq__(self, other):
        return self.__curve_id == other.curve_id

    def __repr__(self):
        return "<OpenSSL Curve(id={}, name={})>".format(self.__curve_id, self.__curve_name)

    #
    # Immutable Curve Data
    #

    @property
    def field_order_size_in_bytes(self) -> int:
        if not self.__field_order_size_in_bytes:
            size_in_bits = openssl._get_ec_group_degree(self.__ec_group)
            self.__field_order_size_in_bytes = (size_in_bits + 7) // 8
        return self.__field_order_size_in_bytes

    @property
    def group_order_size_in_bytes(self) -> int:
        if not self.__group_order_size_in_bytes:
            BN_num_bytes = default_backend()._lib.BN_num_bytes
            self.__group_order_size_in_bytes = BN_num_bytes(self.order)
        return self.__group_order_size_in_bytes

    @property
    def curve_id(self) -> int:
        return self.__curve_id

    @property
    def name(self) -> str:
        return self.__curve_name

    @property
    def ec_group(self):
        return self.__ec_group

    @property
    def order(self):
        return self.__order

    @property
    def generator(self):
        return self.__generator


#
# Global Curve Instances
#

SECP256K1 = Curve.from_name('secp256k1')

CURVES = (SECP256K1)
