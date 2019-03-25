from typing import Optional

from .curve import Curve
from .private_key import PrivateKey
from .public_key import PublicKey


class KeyPair(object):

    def __init__(self, private_key: PrivateKey, public_key: PublicKey) -> None:
        self.private_key = private_key
        self.public_key = public_key

    @classmethod
    def generate_key_pair(cls, curve: Optional[Curve] = None) -> 'KeyPair':

        private_key = PrivateKey.generate(curve)
        public_key = private_key.get_public_key()

        return cls(private_key, public_key)

    def get_private_key(self) -> 'PrivateKey':
        return self.private_key

    def get_public_key(self) -> 'PublicKey':
        return self.public_key
