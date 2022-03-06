import unittest

from gawseed.threatfeed.events.multisummarizer import MultiSummarizer
from collections import Counter


class test_multicounting(unittest.TestCase):
    def test_multi_keys_x2(self):
        m = MultiSummarizer({})

        m.add_keys(['a','b'], {'a': 1, 'b': 2})
        assert m.data == {1: Counter({2: 1})}

        m.add_keys(['a','b'], {'a': 1, 'b': 3}, 12)
        assert m.data == {1: Counter({2: 1, 3: 12})}

        m.add_keys(['a','b'], {'a': 2, 'b': 3}, 42)
        assert m.data == {1: Counter({2: 1, 3: 12}),
                          2: Counter({3: 42})}

        results = m.flatten()
        assert results == [[1,2,1],
                           [1,3,12],
                           [2,3,42]]

    def test_multi_keys_x3(self):
        m = MultiSummarizer({})

        m.add_keys(['a','b', 'c'], {'a': 1, 'b': 2, 'c': 3})
        assert m.data == {1: {2: Counter({3: 1})}}

        m.add_keys(['a','b', 'c'], {'a': 1, 'b': 3, 'c': 3})
        assert m.data == {1: {2: Counter({3: 1}),
                              3: Counter({3: 1})}}

        m.add_keys(['a','b', 'c'], {'a': 1, 'b': 3, 'c': 3})
        assert m.data == {1: {2: Counter({3: 1}),
                              3: Counter({3: 2})}}

        m.add_keys(['a','b','c'], {'a': 2, 'b': 3, 'c': 42})
        assert m.data == {1: {2: Counter({3: 1}),
                              3: Counter({3: 2})},
                          2: {3: Counter({42: 1})}}

        results = m.flatten()
        assert results == [[1,2,3,1],
                           [1,3,3,2],
                           [2,3,42,1]]
