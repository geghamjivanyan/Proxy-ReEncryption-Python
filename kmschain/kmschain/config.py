"""
"""

from typing import Optional

from .curve import Curve, SECP256K1


class Config:
    __curve = None
    __CURVE_IF_NO_DEFAULT = SECP256K1

    @classmethod
    def __set_curve_by_default(cls):
        cls.set_curve(cls.__CURVE_IF_NO_DEFAULT)

    @classmethod
    def curve(cls) -> Curve:
        if not cls.__curve:
            cls.__set_curve_by_default()
        return cls.__curve

    @classmethod
    def set_curve(cls, curve: Optional[Curve] = None) -> None:
        if curve is None:
            curve = Config.__CURVE_IF_NO_DEFAULT
        cls.__curve = curve


def set_default_curve(curve: Optional[Curve] = None) -> None:
    return Config.set_curve(curve)


def default_curve() -> Curve:
    return Config.curve()
