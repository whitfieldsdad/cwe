import collections
import dataclasses
import datetime
import unittest
from typing import List, Optional

from cwe.util import drop_nulls


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


class DropNullsTestCase(unittest.TestCase):
    def test_dict(self):
        self.assertEqual(drop_nulls({'a': 1, 'b': None, 'c': {'d': None, 'e': 2}}), {'a': 1, 'c': {'e': 2}})

    def test_list(self):
        self.assertEqual(drop_nulls([1, None, 2]), [1, 2])

    def test_dicts_within_lists_and_lists_within_dicts(self):
        data = {'a': [{'b': None, 'c': 1}, None, [None, {'d': None}]], 'e': None}
        self.assertEqual(drop_nulls(data), {'a': [{'c': 1}, [{}]]})

    def test_only_none_is_dropped(self):
        data = {'a': '', 'b': 0, 'c': False, 'd': [], 'e': {}, 'f': [None], 'g': {'h': None}}
        self.assertEqual(drop_nulls(data), {'a': '', 'b': 0, 'c': False, 'd': [], 'e': {}, 'f': [], 'g': {}})

    def test_container_types_are_kept(self):
        self.assertEqual(drop_nulls((1, None, [None, 2])), (1, [2]))
        self.assertEqual(drop_nulls({1, None}), {1})
        self.assertEqual(drop_nulls(frozenset({1, None})), frozenset({1}))
        for value in ((1, None), {1, None}, frozenset({None})):
            self.assertIs(type(drop_nulls(value)), type(value))

    def test_named_tuple_keeps_its_fields(self):
        self.assertEqual(drop_nulls(Point(None, {'a': None})), Point(None, {}))

    def test_dataclasses(self):
        data = Outer(name='a', inner=None, inners=[Inner(value=None, items=[1, None]), Inner(value='b', items=[])])
        self.assertEqual(drop_nulls(data), {'name': 'a', 'inners': [{'items': [1]}, {'value': 'b', 'items': []}]})
        self.assertIs(drop_nulls(Outer), Outer)

    def test_scalars_are_returned_as_is(self):
        date = datetime.date(2026, 10, 28)
        for value in (None, 'a', 1, 1.5, True, date):
            self.assertIs(drop_nulls(value), value)

    def test_input_is_not_modified(self):
        data = {'a': None, 'b': [None, {'c': None}]}
        drop_nulls(data)
        self.assertEqual(data, {'a': None, 'b': [None, {'c': None}]})


if __name__ == '__main__':
    unittest.main()
