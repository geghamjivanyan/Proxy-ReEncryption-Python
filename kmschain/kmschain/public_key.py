#
from . group_element import GroupElement


class PublicKey(object):

    def __init__(self, group_element: GroupElement) -> None:
        """
        """

        if not isinstance(group_element, GroupElement):
            raise TypeError("group_element can only be a GroupElement. Don't pass anything else.")

        self.group_element = group_element

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> 'PublicKey':
        """
        """
        point_key = GroupElement.from_bytes(key_bytes)
        return cls(point_key)

    def to_bytes(self, is_compressed: bool = False) -> bytes:
        """
        """
        # TODO: Check size
        public_key = self.group_element.to_bytes(is_compressed=is_compressed)

        return public_key

    def get_group_element(self)-> 'GroupElement':
        return self.group_element
