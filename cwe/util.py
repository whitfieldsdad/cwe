from json import JSONEncoder as _JSONEncoder

import dataclasses
import datetime


class JSONEncoder(_JSONEncoder):
    def default(self, o):
        if isinstance(o, (datetime.date, datetime.datetime)):
            return o.isoformat()
        elif dataclasses.is_dataclass(o):
            o = dataclasses.asdict(o)
            o = drop_null_or_empty(o)
            return o
        elif isinstance(o, dict):
            o = drop_null_or_empty(o)
            return o
        else:
            return super().default(o)


def camel_to_snake(v: str) -> str:
    result = ''.join(['_' + c.lower() if c.isupper() else c for c in v])
    return result.lstrip('_')


def drop_null_or_empty(o):
    """
    Recursively drop `None` and empty values (strings, bytes, and containers) from dicts, lists, tuples, and sets.

    Values are checked after they've been cleaned, so containers that only hold null or empty values are dropped too.
    Falsy scalars such as `0` and `False` are kept, and the top-level value is always returned, even if it's empty.
    """
    if dataclasses.is_dataclass(o) and not isinstance(o, type):
        o = {f.name: getattr(o, f.name) for f in dataclasses.fields(o)}

    if isinstance(o, dict):
        items = ((k, drop_null_or_empty(v)) for k, v in o.items())
        return {k: v for k, v in items if not _is_null_or_empty(v)}
    if isinstance(o, tuple) and hasattr(o, '_fields'):
        return type(o)(*(drop_null_or_empty(v) for v in o))  # Named tuples have a fixed number of fields
    if isinstance(o, (list, tuple, set, frozenset)):
        values = (drop_null_or_empty(v) for v in o)
        return type(o)(v for v in values if not _is_null_or_empty(v))
    return o


def _is_null_or_empty(o) -> bool:
    if o is None:
        return True
    return isinstance(o, (str, bytes, dict, list, tuple, set, frozenset)) and len(o) == 0
