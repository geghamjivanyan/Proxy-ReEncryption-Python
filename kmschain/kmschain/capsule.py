from typing import Optional

from . import config
from . scalar import Scalar
from . group_element import GroupElement
from . curve import Curve


class Capsule(object):

    def __init__(self,
                 E: GroupElement,
                 V: GroupElement,
                 S: Scalar,
                 XG: Optional[GroupElement] = None,
                 re_encrypted: bool = False) -> None:

        self.E = E
        self.V = V
        self.S = S
        self.XG = XG
        self.re_encrypted = re_encrypted

    def get_E(self) -> 'GroupElement':
        return self.E

    def get_V(self) -> 'GroupElement':
        return self.V

    def get_S(self) -> 'Scalar':
        return self.S

    def get_XG(self) -> 'GroupElement':
        return self.XG

    def is_re_encrypted(self) -> bool:
        return self.re_encrypted

    def set_re_encrypted(self) -> None:
        self.re_encrypted = True

    @classmethod
    def from_bytes(cls, key_bytes: bytes, curve: Optional[Curve] = None) -> 'Capsule':

        curve = curve if curve is not None else config.default_curve()

        sc_size = Scalar.expected_bytes_length(curve)
        ge_size = GroupElement.expected_bytes_length(curve)

        E = GroupElement.from_bytes(key_bytes[:ge_size])
        V = GroupElement.from_bytes(key_bytes[ge_size:2*ge_size])
        S = Scalar.from_bytes(key_bytes[2*ge_size:2*ge_size+sc_size])
        XG = GroupElement.from_bytes(key_bytes[2*ge_size+sc_size:]) if len(key_bytes) > 2*ge_size + sc_size else None
        re_encrypted = False if XG is None else True

        return cls(E, V, S, XG, re_encrypted)

    def to_bytes(self) -> bytes:
        E = self.E.to_bytes()
        V = self.V.to_bytes()
        S = self.S.to_bytes()
        XG = b''
        if self.is_re_encrypted():
            XG = self.XG.to_bytes()

        capsule_bytes = E + V + S + XG
        return capsule_bytes
