#
from proxy_test import BaseTest

#
from kmschain.scalar import Scalar
from kmschain.group_element import GroupElement


class TestMath(BaseTest):
    #
    def setUp(self):
        super(TestMath, self).setUp()

    def test_scalar_add(self):
        """
        Scalar test - Add
        """
        print("\nSCALAR TEST - ADD\n")

        sc_1 = Scalar.generate_random()
        sc_2 = Scalar.generate_random()

        sc_12 = sc_1 + sc_2
        sc_21 = sc_2 + sc_1

        self.assertEqual(sc_12.to_bytes(), sc_21.to_bytes())

    def test_scalar_sub(self):
        """
        Scalar test - Sub
        """
        print("\nSCALAR TEST - SUB\n")
        sc_1 = Scalar.generate_random()
        sc_2 = Scalar.generate_random()

        sc_12 = sc_1 + sc_2
        sc_2_back = sc_12 - sc_1

        self.assertEqual(sc_2.to_bytes(), sc_2_back.to_bytes())

        sc_3 = Scalar.generate_random()

        sc_123 = sc_1 + sc_2 + sc_3
        sc_23 = sc_2 + sc_3

        sc_1_back = sc_123 - sc_23
        self.assertEqual(sc_1.to_bytes(), sc_1_back.to_bytes())

    def test_scalar_mul(self):
        """
        Scalar test - Mul
        """
        print("\nSCALAR TEST - MUL\n")

        sc_1 = Scalar.generate_random()
        sc_2 = Scalar.generate_random()

        sc_12 = sc_1 * sc_2
        sc_21 = sc_2 * sc_1

        self.assertEqual(sc_12.to_bytes(), sc_21.to_bytes())

    def test_scalar_div(self):
        """
        Scalar test - Div
        """
        print("\nSCALAR TEST - DIV\n")
        sc_1 = Scalar.generate_random()
        sc_2 = Scalar.generate_random()

        sc_12 = sc_1 * sc_2
        sc_2_back = sc_12 / sc_1

        self.assertEqual(sc_2.to_bytes(), sc_2_back.to_bytes())

        sc_3 = Scalar.generate_random()

        sc_123 = sc_1 * sc_2 * sc_3
        sc_23 = sc_2 * sc_3

        sc_1_back = sc_123 / sc_23
        self.assertEqual(sc_1.to_bytes(), sc_1_back.to_bytes())

    def test_group_element_add(self):
        """
        GroupElement test - Add
        """

        print("\nGROUP ELEMENT TEST - ADD\n")
        ge_1 = GroupElement.generate_random()
        ge_2 = GroupElement.generate_random()
        ge_12 = ge_1 + ge_2
        ge_21 = ge_2 + ge_1

        self.assertEqual(ge_12.to_bytes(), ge_21.to_bytes())

    def test_group_element_mul(self):
        """
        GroupElement test - Mul
        """

        print("\nGROUP ELEMENT TEST - MUL\n")

        ge = GroupElement.generate_random()
        sc = Scalar.generate_random()

        ge_new = ge * sc

        assert isinstance(ge_new, GroupElement)
