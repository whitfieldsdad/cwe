from json import JSONEncoder as _JSONEncoder

import dataclasses
import datetime


class JSONEncoder(_JSONEncoder):
    def default(self, o):
        if isinstance(o, (datetime.date, datetime.datetime)):
            return o.isoformat()
        elif dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        else:
            return super().default(o)


def drop_nulls_from_dict(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is not None}
