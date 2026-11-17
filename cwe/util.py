from json import JSONEncoder as _JSONEncoder

import dataclasses
import datetime


class JSONEncoder(_JSONEncoder):
    def default(self, o):
        if isinstance(o, (datetime.date, datetime.datetime)):
            return o.isoformat()
        elif dataclasses.is_dataclass(o):
            o = dataclasses.asdict(o)
            o = drop_nulls(o)
            return o
        elif isinstance(o, dict):
            o = drop_nulls(o)
            return o
        else:
            return super().default(o)


def camel_to_snake(v: str) -> str:
    result = ''.join(['_' + c.lower() if c.isupper() else c for c in v])
    return result.lstrip('_')


def drop_nulls(o):
    if dataclasses.is_dataclass(o) and not isinstance(o, type):
        o = {f.name: getattr(o, f.name) for f in dataclasses.fields(o)}

    if isinstance(o, dict):
        return {k: drop_nulls(v) for k, v in o.items() if v is not None}
    if isinstance(o, tuple) and hasattr(o, '_fields'):
        return type(o)(*(drop_nulls(v) for v in o))  # Named tuples have a fixed number of fields
    if isinstance(o, (list, tuple, set, frozenset)):
        return type(o)(drop_nulls(v) for v in o if v is not None)
    return o
