
from typing import Optional

from . import config
from .scalar import Scalar
from .group_element import GroupElement
from .curve import Curve


class ReEncryptionKey(object):

    def __init__(self, re_key: Scalar, internal_public_key: GroupElement) -> None:
        self.__re_key = re_key
        self.__internal_public_key = internal_public_key

    def get_re_key(self) -> 'Scalar':
        return self.__re_key

    def get_internal_public_key(self) -> 'GroupElement':
        return self.__internal_public_key

    @classmethod
    def from_bytes(cls, key_bytes: bytes, curve: Optional[Curve] = None) -> 'ReEncryptionKey':
        curve = curve if curve is not None else config.default_curve()

        sc_size = Scalar.expected_bytes_length(curve)
        # TODO: Check size
        re_key = Scalar.from_bytes(key_bytes[:sc_size])
        internal_public_key = GroupElement.from_bytes(key_bytes[sc_size:])

        return cls(re_key, internal_public_key)

    def to_bytes(self) -> bytes:
        re_key = self.__re_key.to_bytes()
        internal_public_key = self.__internal_public_key.to_bytes()

        rk_bytes = re_key + internal_public_key
        return rk_bytes
