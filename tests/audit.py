"""
Black-box audit of the parser: checks that every attribute value and every piece of text in a CWE XML file is present
in the parsed catalog.

Usage: python -m tests.audit <path to CWE XML file>
"""
import collections
import dataclasses
import sys
import xml.etree.ElementTree as ET
from typing import Dict, Iterator, List, Tuple

from cwe import parser

XHTML = "{http://www.w3.org/1999/xhtml}"

# Values which are intentionally transformed or dropped by the parser.
PUBLICATION_DATE_PARTS = {"Publication_Year", "Publication_Month", "Publication_Day"}
DROPPED_VALUES = {("Likelihood", "Unknown")}


def _local_name(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _squash(text: str) -> str:
    # Whitespace is not significant, and `|` is escaped within Markdown tables.
    return "".join(text.split()).replace("\\|", "|")


def _strings(value) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)


def _text_chunks(element: ET.Element) -> Iterator[str]:
    yield element.text or ""
    for child in element:
        if _local_name(child) == "img":
            yield child.get("alt", "")
            yield child.get("src", "")
        yield from _text_chunks(child)
        yield child.tail or ""


def audit_item(element: ET.Element, parsed) -> Iterator[Tuple[str, bool, str]]:
    """
    Yield (path, found, value) for every attribute and text value within an element.
    """
    leaves = {_squash(s) for s in _strings(dataclasses.asdict(parsed))}
    blob = "\x00".join(leaves)
    date = getattr(parsed, "publication_date", None) or ""

    def walk(e: ET.Element, path: str):
        tag = _local_name(e)
        for name, value in e.attrib.items():
            yield f"{path}/@{name}", _squash(value) in leaves, value

        if any(child.tag.startswith(XHTML) for child in e):
            chunks = [_squash(c) for c in _text_chunks(e)]
            missing = [c for c in chunks if c and c not in blob]
            yield f"{path} (XHTML)", not missing, " | ".join(missing)[:200]
            return

        text = (e.text or "").strip()
        if text:
            if tag in PUBLICATION_DATE_PARTS:
                found = text.lstrip("-") in date.split("-")
            elif (tag, text) in DROPPED_VALUES:
                found = True
            else:
                found = _squash(text) in leaves
            yield path, found, text[:200]

        for child in e:
            yield from walk(child, f"{path}/{_local_name(child)}")

    yield from walk(element, _local_name(element))


def audit_file(path: str) -> Tuple[Dict[str, List[int]], List[Tuple[str, str, str]]]:
    """
    Returns ({path: [found, total]}, [(item ID, path, missing value)]).
    """
    root = ET.parse(path).getroot()
    catalog = parser.parse_weakness_catalog(root)
    sections = [
        ("Weaknesses", catalog.weaknesses),
        ("Groupings", catalog.groupings),
        ("Categories", catalog.groupings),
        ("Views", catalog.views),
        ("External_References", catalog.external_references),
    ]
    summary = collections.defaultdict(lambda: [0, 0])
    failures = []
    seen = set()
    for section in root:
        name = _local_name(section)
        seen.add(name)
        parsed = next((items for n, items in sections if n == name), None)
        if parsed is None:
            summary[f"{name} (section)"][1] += 1
            failures.append(("-", name, "unparsed section"))
            continue
        assert len(parsed) == len(section), name
        for element, item in zip(section, parsed):
            for path, found, value in audit_item(element, item):
                summary[path][0] += found
                summary[path][1] += 1
                if not found:
                    failures.append((item.id, path, value))
    return dict(summary), failures


def main(path: str) -> int:
    summary, failures = audit_file(path)
    for path in sorted(summary):
        found, total = summary[path]
        print(f"{'OK  ' if found == total else 'MISS'} {found:>6}/{total:<6} {path}")
    print(f"\n{len(summary)} paths, {len(failures)} missing values")
    for item_id, path, value in failures[:40]:
        print(f"  {item_id}: {path}: {value!r}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
