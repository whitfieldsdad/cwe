import datetime
from typing import Any, Dict, List, Optional, Union

import json
import dataclasses


class JSONEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, datetime.date):
            return o.isoformat()
        elif dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return super().default(o)


def print_json(o: Any):
    print(json.dumps(o, cls=JSONEncoder))


def drop_empty(o: dict) -> dict:
    d = {}
    for k, v in o.items():
        if not (v or None) is None:
            d[k] = v
    return d


def as_list(o: Any) -> List:
    return [o] if isinstance(o, str) else o
        


def as_dicts(o: Any, lowercase: bool = False) -> List[dict]:
    if isinstance(o, dict):
        rows = [o]
    elif isinstance(o, list) and all(isinstance(x, dict) for x in o):
        rows = o
    else:
        raise ValueError("Expected a dict or a list of dicts")
    
    if lowercase:
        rows = [lowercase_dict(row) for row in rows]
    
    return rows


def lowercase_dict(o: dict) -> dict:
    return {k.lower(): v for k, v in o.items()}


def inv_1_to_m(d: Dict[str, List[str]]) -> Dict[str, List[str]]:
    m = {}
    for k, vs in d.items():
        for v in vs:
            if k not in m:
                m[k] = [v]
            else:
                m[k] = sorted(m[k] + [v])
    return m


def parse_date(t: Union[str, datetime.date, datetime.datetime]) -> Optional[datetime.date]:
    if t is not None:
        if isinstance(t, datetime.date):
            return t
        elif isinstance(t, datetime.datetime):
            return t.date()
        elif isinstance(t, str):
            return datetime.datetime.strptime(t, '%Y-%m-%d').date()
        else:
            raise ValueError(f"Expected a datetime.date, datetime.datetime, or str, got {t!r}")
