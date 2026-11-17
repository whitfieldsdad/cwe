import collections
import dataclasses
import datetime
import unittest
from typing import List, Optional

from cwe.util import drop_null_or_empty


@dataclasses.dataclass()
class Inner:
    value: Optional[str]
    items: List[Optional[int]]


@dataclasses.dataclass()
class Outer:
    name: str
    inner: Optional[Inner]
    inners: List[Inner]


Point = collections.namedtuple('Point', ['x', 'y'])


class DropNullOrEmptyTestCase(unittest.TestCase):
    def test_dict(self):
        self.assertEqual(drop_null_or_empty({'a': 1, 'b': None, 'c': {'d': None, 'e': 2}}), {'a': 1, 'c': {'e': 2}})

    def test_list(self):
        self.assertEqual(drop_null_or_empty([1, None, 2]), [1, 2])

    def test_dicts_within_lists_and_lists_within_dicts(self):
        data = {'a': [{'b': None, 'c': 1}, None, [None, {'d': None}]], 'e': None}
        self.assertEqual(drop_null_or_empty(data), {'a': [{'c': 1}]})

    def test_empty_values_are_dropped(self):
        data = {'a': '', 'b': b'', 'c': [], 'd': {}, 'e': (), 'f': set(), 'g': frozenset(), 'h': 1}
        self.assertEqual(drop_null_or_empty(data), {'h': 1})
        self.assertEqual(drop_null_or_empty([1, '', [], {}, 2]), [1, 2])

    def test_values_that_become_empty_are_dropped(self):
        data = {'a': [None], 'b': {'c': None}, 'd': [[''], {'e': [{}]}], 'f': 1}
        self.assertEqual(drop_null_or_empty(data), {'f': 1})

    def test_falsy_scalars_are_kept(self):
        data = {'a': 0, 'b': False, 'c': 0.0, 'd': ' '}
        self.assertEqual(drop_null_or_empty(data), data)
        self.assertEqual(drop_null_or_empty([0, False]), [0, False])

    def test_top_level_value_is_kept_when_empty(self):
        self.assertEqual(drop_null_or_empty({'a': None}), {})
        self.assertEqual(drop_null_or_empty([None, '']), [])
        self.assertEqual(drop_null_or_empty(''), '')

    def test_container_types_are_kept(self):
        self.assertEqual(drop_null_or_empty((1, None, [None, 2])), (1, [2]))
        self.assertEqual(drop_null_or_empty({1, None}), {1})
        self.assertEqual(drop_null_or_empty(frozenset({1, None})), frozenset({1}))
        for value in ((1, None), {1, None}, frozenset({None})):
            self.assertIs(type(drop_null_or_empty(value)), type(value))

    def test_named_tuple_keeps_its_fields(self):
        self.assertEqual(drop_null_or_empty(Point(None, {'a': None})), Point(None, {}))

    def test_dataclasses(self):
        data = Outer(name='a', inner=None, inners=[Inner(value=None, items=[1, None]), Inner(value='b', items=[])])
        self.assertEqual(drop_null_or_empty(data), {'name': 'a', 'inners': [{'items': [1]}, {'value': 'b'}]})
        self.assertIs(drop_null_or_empty(Outer), Outer)

    def test_scalars_are_returned_as_is(self):
        date = datetime.date(2026, 10, 28)
        for value in (None, 'a', 1, 1.5, True, date):
            self.assertIs(drop_null_or_empty(value), value)

    def test_input_is_not_modified(self):
        data = {'a': None, 'b': [None, {'c': None}]}
        drop_null_or_empty(data)
        self.assertEqual(data, {'a': None, 'b': [None, {'c': None}]})


if __name__ == '__main__':
    unittest.main()
