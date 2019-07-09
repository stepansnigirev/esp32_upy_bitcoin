from unittest import TestCase

from bitcoin.ecc import (
    PrivateKey, 
    PublicKey, 
    Signature,
    G,
)


class PublicKeyTest(TestCase):

    def test_ne(self):
        self.assertTrue(G != G*2)
        self.assertFalse(G != G)

    def test_on_curve(self):
        with self.assertRaises(ValueError):
            PublicKey(x=-2, y=4)
        # these should not raise an error
        PublicKey(G.x, G.y)

    def test_add(self):
        want = PublicKey(
            0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5, 
            0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a,
        )
        self.assertEqual(G + G, want)

    def test_multiply(self):
        want = PublicKey(
            0xa0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7, 
            0x893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7,
        )
        self.assertEqual(G * 10, want)

