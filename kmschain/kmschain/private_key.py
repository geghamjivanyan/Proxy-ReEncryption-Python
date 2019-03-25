from typing import Optional

from .scalar import Scalar
from .group_element import GroupElement
from .curve import Curve
from .public_key import PublicKey


class PrivateKey(object):

    def __init__(self, scalar: Scalar) -> None:
        self.__scalar = scalar
        self.__public_key = PublicKey(self.__scalar * GroupElement.get_generator_from_curve())

    @classmethod
    def generate(cls, curve: Optional[Curve] = None) -> 'PrivateKey':
        """
        Generates a private key and returns it.
        """
        scalar = Scalar.generate_random(curve)
        return cls(scalar)

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> 'PrivateKey':
        """
        """
        scalar = Scalar.from_bytes(key_bytes)
        return cls(scalar)

    def to_bytes(self) -> bytes:
        """
        """

        key_bytes = self.__scalar.to_bytes()
        return key_bytes

    def get_public_key(self) -> 'PublicKey':
        """
        Calculates and returns the public key of the private key.
        """
        return self.__public_key

    @property
    def value(self):
        return self.__scalar
