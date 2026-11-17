from typing import List, Optional

from cwe.types import (
    WeaknessCatalog,
    Weakness,
    WeaknessOrdinality,
    WeaknessReference,
    ModeOfIntroduction,
    DetectionMethod,
    Mitigation,
    CustomPhase,
    DemonstrativeExample,
    DemonstrativeExampleBlock,
    ObservedExample,
    PlatformReference,
    TaxonomyMapping,
    MappingNotes,
    MappingSuggestion,
    Dimension,
    AlternateTerm,
    Note,
    Submission,
    Modification,
    Contribution,
    PreviousEntryName,
    Grouping,
    View,
    Stakeholder,
    ExternalReference,
    ExternalReferenceCitation,
    Consequence,
)
import dacite
import datetime
import textwrap
import xml.etree.ElementTree as ET

HAS_MEMBER = "HasMember"

_LINE_BREAK = "\x00"
_CODE_INDENT = "    "


def parse_cwe_xml_file(path: str) -> WeaknessCatalog:
    return parse_weakness_catalog(ET.parse(path).getroot())


def parse_weakness_catalog(o: ET.Element) -> WeaknessCatalog:
    # Groupings were named categories prior to version 5.0 of the catalog.
    groupings = _find_all(o, "Groupings/Grouping") + _find_all(o, "Categories/Category")

    data = {
        "name": o.attrib["Name"],
        "version": o.attrib["Version"],
        "date": datetime.date.fromisoformat(o.attrib["Date"]),
        "weaknesses": [parse_weakness(w) for w in _find_all(o, "Weaknesses/Weakness")],
        "groupings": [parse_grouping(g) for g in groupings],
        "views": [parse_view(v) for v in _find_all(o, "Views/View")],
        "external_references": [
            parse_external_reference(r)
            for r in _find_all(o, "External_References/External_Reference")
        ],
    }
    return dacite.from_dict(WeaknessCatalog, data)


def parse_weakness(o: ET.Element) -> Weakness:
    data = {
        "id": o.attrib["ID"],
        "name": o.attrib["Name"],
        "abstraction": o.attrib["Abstraction"],
        "structure": o.attrib["Structure"],
        "status": o.attrib["Status"],
        "diagram": o.get("Diagram"),
        "description": _get_optional_str(o, "Description"),
        "extended_description": _get_optional_str(o, "Extended_Description"),
        "background_details": _get_list_of_str(
            o, "Background_Details/Background_Detail"
        ),
        "technical_nuance": _get_optional_str(o, "Technical_Nuance"),
        "alternate_terms": [
            parse_alternate_term(t)
            for t in _find_all(o, "Alternate_Terms/Alternate_Term")
        ],
        "likelihood_of_exploitation": _get_optional_str(o, "Likelihood_Of_Exploit"),
        "weakness_ordinalities": [
            parse_weakness_ordinality(w)
            for w in _find_all(o, "Weakness_Ordinalities/Weakness_Ordinality")
        ],
        "applicable_platforms": [
            parse_platform_reference(p) for p in _find_all(o, "Applicable_Platforms/*")
        ],
        "modes_of_introduction": [
            parse_mode_of_introduction(m)
            for m in _find_all(o, "Modes_Of_Introduction/Introduction")
        ],
        "common_consequences": [
            parse_consequence(c)
            for c in _find_all(o, "Common_Consequences/Consequence")
        ],
        "detection_methods": [
            parse_detection_method(d)
            for d in _find_all(o, "Detection_Methods/Detection_Method")
        ],
        "potential_mitigations": [
            parse_mitigation(m) for m in _find_all(o, "Potential_Mitigations/Mitigation")
        ],
        "demonstrative_examples": [
            parse_demonstrative_example(d)
            for d in _find_all(o, "Demonstrative_Examples/Demonstrative_Example")
        ],
        "observed_examples": [
            parse_observed_example(e)
            for e in _find_all(o, "Observed_Examples/Observed_Example")
        ],
        "related_weaknesses": [
            parse_weakness_reference(r)
            for r in _find_all(o, "Related_Weaknesses/Related_Weakness")
        ],
        "related_attack_patterns": [
            r.attrib["CAPEC_ID"]
            for r in _find_all(o, "Related_Attack_Patterns/Related_Attack_Pattern")
        ],
        "functional_areas": _get_list_of_str(o, "Functional_Areas/Functional_Area"),
        "affected_resources": _get_list_of_str(
            o, "Affected_Resources/Affected_Resource"
        ),
        "dimensions": _parse_dimensions(o),
        **_parse_common_fields(o),
    }
    return dacite.from_dict(Weakness, data)


def parse_weakness_ordinality(o: ET.Element) -> WeaknessOrdinality:
    data = {
        "ordinality": _get_optional_str(o, "Ordinality"),
        "description": _get_optional_str(o, "Description"),
    }
    return dacite.from_dict(WeaknessOrdinality, data)


def parse_weakness_reference(o: ET.Element) -> WeaknessReference:
    """
    Parse a `Related_Weakness` element, or a `Has_Member` element of a grouping or view.
    """
    data = {
        "cwe_id": o.attrib["CWE_ID"],
        "view_id": o.get("View_ID"),
        "nature": HAS_MEMBER if _local_name(o) == "Has_Member" else o.get("Nature"),
        "ordinal": o.get("Ordinal"),
        "chain_id": o.get("Chain_ID"),
        "dimensions": _parse_dimensions(o),
    }
    return dacite.from_dict(WeaknessReference, data)


def parse_platform_reference(o: ET.Element) -> PlatformReference:
    """
    Parse a `Language`, `Operating_System`, `Architecture`, or `Technology` element.
    """
    data = {
        "type": _local_name(o).replace("_", " "),
        "name": o.get("Name"),
        "platform_class": o.get("Class"),
        "prevalence": o.get("Prevalence"),
        "note": _get_optional_str(o, "Note"),
    }
    return dacite.from_dict(PlatformReference, data)


def parse_alternate_term(o: ET.Element) -> AlternateTerm:
    data = {
        "name": _get_optional_str(o, "Term"),
        "description": _get_optional_str(o, "Description"),
        "roles": _get_list_of_str(o, "Role"),
    }
    return dacite.from_dict(AlternateTerm, data)


def parse_consequence(o: ET.Element) -> Consequence:
    likelihood = _get_optional_str(o, "Likelihood")
    if likelihood == "Unknown":
        likelihood = None

    data = {
        "scope": sorted(_get_list_of_str(o, "Scope")),
        "impact": sorted(_get_list_of_str(o, "Impact")),
        "likelihood": likelihood,
        "note": _get_optional_str(o, "Note"),
    }
    return dacite.from_dict(Consequence, data)


def parse_mode_of_introduction(o: ET.Element) -> ModeOfIntroduction:
    data = {
        "phase": sorted(_get_list_of_str(o, "Phase")),
        "custom_phases": _parse_custom_phases(o),
        "note": _get_optional_str(o, "Note"),
    }
    return dacite.from_dict(ModeOfIntroduction, data)


def parse_detection_method(o: ET.Element) -> DetectionMethod:
    data = {
        "id": o.get("Detection_Method_ID"),
        "name": _get_optional_str(o, "Method"),
        "phase": sorted(_get_list_of_str(o, "Phase")),
        "custom_phases": _parse_custom_phases(o),
        "description": _get_optional_str(o, "Description"),
        "effectiveness": _get_optional_str(o, "Effectiveness"),
        "effectiveness_notes": _get_optional_str(o, "Effectiveness_Notes"),
    }
    return dacite.from_dict(DetectionMethod, data)


def parse_mitigation(o: ET.Element) -> Mitigation:
    data = {
        "id": o.get("Mitigation_ID"),
        "phase": sorted(_get_list_of_str(o, "Phase")),
        "custom_phases": _parse_custom_phases(o),
        "strategy": _get_optional_str(o, "Strategy"),
        "description": _get_optional_str(o, "Description"),
        "effectiveness": _get_optional_str(o, "Effectiveness"),
        "effectiveness_notes": _get_optional_str(o, "Effectiveness_Notes"),
    }
    return dacite.from_dict(Mitigation, data)


def parse_demonstrative_example(o: ET.Element) -> DemonstrativeExample:
    # Text and code are interleaved, so the blocks are kept in document order.
    body = []
    for child in o:
        tag = _local_name(child)
        if tag in ("Body_Text", "Example_Code"):
            is_code = tag == "Example_Code"
            block = {
                "type": "code" if is_code else "text",
                "content": _get_code(child) if is_code else _get_text(child),
                "nature": child.get("Nature"),
                "language": child.get("Language"),
            }
            if block["content"]:
                body.append(dacite.from_dict(DemonstrativeExampleBlock, block))

    data = {
        "id": o.get("Demonstrative_Example_ID"),
        "intro_text": _get_optional_str(o, "Intro_Text"),
        "body": body,
        "references": [
            parse_external_reference_citation(r)
            for r in _find_all(o, "References/Reference")
        ],
    }
    return dacite.from_dict(DemonstrativeExample, data)


def parse_observed_example(o: ET.Element) -> ObservedExample:
    data = {
        "reference": _get_optional_str(o, "Reference"),
        "description": _get_optional_str(o, "Description"),
        "link": _get_optional_str(o, "Link"),
        "rationales": _get_list_of_str(o, "Rationale"),
    }
    return dacite.from_dict(ObservedExample, data)


def parse_taxonomy_mapping(o: ET.Element) -> TaxonomyMapping:
    data = {
        "taxonomy_name": o.attrib["Taxonomy_Name"],
        "entry_id": _get_optional_str(o, "Entry_ID"),
        "entry_name": _get_optional_str(o, "Entry_Name"),
        "mapping_fit": _get_optional_str(o, "Mapping_Fit"),
    }
    return dacite.from_dict(TaxonomyMapping, data)


def parse_mapping_notes(o: ET.Element) -> MappingNotes:
    suggestions = [
        dacite.from_dict(
            MappingSuggestion, {"cwe_id": s.attrib["CWE_ID"], "comment": s.get("Comment")}
        )
        for s in _find_all(o, "Suggestions/Suggestion")
    ]
    data = {
        "usage": _get_optional_str(o, "Usage"),
        "rationale": _get_optional_str(o, "Rationale"),
        "comments": _get_optional_str(o, "Comments"),
        "reasons": [r.attrib["Type"] for r in _find_all(o, "Reasons/Reason")],
        "suggestions": suggestions,
    }
    return dacite.from_dict(MappingNotes, data)


def parse_note(o: ET.Element) -> Note:
    data = {
        "note_type": o.get("Type"),
        "value": _get_text(o),
        "version": o.get("Version"),
        "release_date": o.get("ReleaseDate"),
    }
    return dacite.from_dict(Note, data)


def parse_external_reference_citation(o: ET.Element) -> ExternalReferenceCitation:
    data = {
        "external_reference_id": o.attrib["External_Reference_ID"],
        "section": o.get("Section"),
    }
    return dacite.from_dict(ExternalReferenceCitation, data)


def parse_submission(o: ET.Element) -> Submission:
    data = {
        "names": _get_list_of_str(o, "Submission_Name"),
        "organization": _get_optional_str(o, "Submission_Organization"),
        "date": _get_optional_str(o, "Submission_Date"),
        "version": _get_optional_str(o, "Submission_Version"),
        "release_date": _get_optional_str(o, "Submission_ReleaseDate"),
        "comment": _get_optional_str(o, "Submission_Comment"),
    }
    return dacite.from_dict(Submission, data)


def parse_modification(o: ET.Element) -> Modification:
    data = {
        "name": _get_optional_str(o, "Modification_Name"),
        "organization": _get_optional_str(o, "Modification_Organization"),
        "date": _get_optional_str(o, "Modification_Date"),
        "version": _get_optional_str(o, "Modification_Version"),
        "release_date": _get_optional_str(o, "Modification_ReleaseDate"),
        "comment": _get_optional_str(o, "Modification_Comment"),
        "importance": _get_optional_str(o, "Modification_Importance"),
    }
    return dacite.from_dict(Modification, data)


def parse_contribution(o: ET.Element) -> Contribution:
    data = {
        "type": o.get("Type"),
        "names": _get_list_of_str(o, "Contribution_Name"),
        "organization": _get_optional_str(o, "Contribution_Organization"),
        "date": _get_optional_str(o, "Contribution_Date"),
        "version": _get_optional_str(o, "Contribution_Version"),
        "release_date": _get_optional_str(o, "Contribution_ReleaseDate"),
        "comment": _get_optional_str(o, "Contribution_Comment"),
    }
    return dacite.from_dict(Contribution, data)


def parse_previous_entry_name(o: ET.Element) -> PreviousEntryName:
    data = {"name": _get_text(o), "date": o.get("Date"), "version": o.get("Version")}
    return dacite.from_dict(PreviousEntryName, data)


def parse_grouping(o: ET.Element) -> Grouping:
    data = {
        "id": o.attrib["ID"],
        "name": o.attrib["Name"],
        "description": _get_optional_str(o, "Summary"),
        "status": o.attrib["Status"],
        "members": [
            parse_weakness_reference(m) for m in _find_all(o, "Relationships/Has_Member")
        ],
        **_parse_common_fields(o),
    }
    return dacite.from_dict(Grouping, data)


def parse_view(o: ET.Element) -> View:
    data = {
        "id": o.attrib["ID"],
        "name": o.attrib["Name"],
        "type": o.attrib["Type"],
        "status": o.attrib["Status"],
        "objective": _get_optional_str(o, "Objective"),
        "audience": [
            parse_stakeholder(s) for s in _find_all(o, "Audience/Stakeholder")
        ],
        "members": [
            parse_weakness_reference(m) for m in _find_all(o, "Members/Has_Member")
        ],
        "filter": _get_optional_str(o, "Filter"),
        **_parse_common_fields(o),
    }
    data.pop("taxonomy_mappings")
    return dacite.from_dict(View, data)


def parse_stakeholder(o: ET.Element) -> Stakeholder:
    data = {
        "type": _get_optional_str(o, "Type"),
        "description": _get_optional_str(o, "Description"),
    }
    return dacite.from_dict(Stakeholder, data)


def parse_external_reference(o: ET.Element) -> ExternalReference:
    data = {
        "id": o.attrib["Reference_ID"],
        "name": _get_optional_str(o, "Title"),
        "authors": _get_list_of_str(o, "Author"),
        "publication_date": _extract_external_reference_publication_date(o),
        "edition": _get_optional_str(o, "Edition"),
        "publication": _get_optional_str(o, "Publication"),
        "publisher": _get_optional_str(o, "Publisher"),
        "url": _get_optional_str(o, "URL"),
        "url_date": _get_optional_str(o, "URL_Date"),
        "alt_url": _get_optional_str(o, "Alt_URL"),
        "alt_url_date": _get_optional_str(o, "Alt_URL_Date"),
        "access_restrictions": _get_optional_str(o, "Access_Restrictions"),
        "media_types": _get_list_of_str(o, "Media_Type"),
        "rationales": _get_list_of_str(o, "Rationale"),
    }
    return dacite.from_dict(ExternalReference, data)


def _extract_external_reference_publication_date(o: ET.Element) -> Optional[str]:
    """
    Read the publication date as an ISO 8601 string at the precision provided (`YYYY`, `YYYY-MM`, or `YYYY-MM-DD`).

    Publication months and days use the `gMonth` (`--MM`) and `gDay` (`---DD`) formats.
    """
    parts = []
    for key in ("Publication_Year", "Publication_Month", "Publication_Day"):
        value = _get_optional_str(o, key)
        if value is None:
            break
        parts.append(value.lstrip("-"))
    return "-".join(parts) or None


def _parse_common_fields(o: ET.Element) -> dict:
    """
    Parse the fields which are shared by weaknesses, groupings, and views.
    """
    mapping_notes = _find(o, "Mapping_Notes")
    return {
        "taxonomy_mappings": [
            parse_taxonomy_mapping(t)
            for t in _find_all(o, "Taxonomy_Mappings/Taxonomy_Mapping")
        ],
        "references": [
            parse_external_reference_citation(r)
            for r in _find_all(o, "References/Reference")
        ],
        "mapping_notes": (
            parse_mapping_notes(mapping_notes) if mapping_notes is not None else None
        ),
        "notes": [n for n in map(parse_note, _find_all(o, "Notes/Note")) if n.value],
        "submission_history": [
            parse_submission(s) for s in _find_all(o, "Content_History/Submission")
        ],
        "modification_history": [
            parse_modification(m) for m in _find_all(o, "Content_History/Modification")
        ],
        "contribution_history": [
            parse_contribution(c) for c in _find_all(o, "Content_History/Contribution")
        ],
        "previous_entry_names": [
            parse_previous_entry_name(p)
            for p in _find_all(o, "Content_History/Previous_Entry_Name")
        ],
    }


def _parse_custom_phases(o: ET.Element) -> List[CustomPhase]:
    return [
        dacite.from_dict(CustomPhase, {"name": _get_text(p), "domain": p.get("Domain")})
        for p in _find_all(o, "Custom_Phase")
    ]


def _parse_dimensions(o: ET.Element) -> List[Dimension]:
    return [
        dacite.from_dict(Dimension, {"type": d.attrib["Type"], "value": _get_text(d)})
        for d in _find_all(o, "Dimensions/Dimension")
    ]


def _path(path: str) -> str:
    # Elements are matched by local name so that the parser does not depend on the version of the CWE namespace.
    return "/".join("{*}" + tag for tag in path.split("/"))


def _find(o: ET.Element, path: str) -> Optional[ET.Element]:
    return o.find(_path(path))


def _find_all(o: ET.Element, path: str) -> List[ET.Element]:
    return o.findall(_path(path))


def _get_text(element: ET.Element) -> Optional[str]:
    """
    Read the text of an element. XHTML blocks are rendered as Markdown, whitespace within plain text is collapsed
    (the document is pretty-printed, so line breaks within plain text are not significant), and empty values are
    returned as None.
    """
    if len(element):
        text = xhtml_to_markdown(element)
    else:
        text = " ".join((element.text or "").split())
    return text or None


def _get_code(element: ET.Element) -> Optional[str]:
    """
    Read the text of an `Example_Code` element, preserving line breaks and indentation.
    """
    if len(element):
        return xhtml_to_code(element) or None

    lines = textwrap.dedent((element.text or "").expandtabs()).splitlines()
    return "\n".join(line.rstrip() for line in lines).strip("\n") or None


def _get_optional_str(o: ET.Element, path: str) -> Optional[str]:
    element = _find(o, path)
    return _get_text(element) if element is not None else None


def _get_list_of_str(o: ET.Element, path: str) -> List[str]:
    texts = (_get_text(element) for element in _find_all(o, path))
    return [text for text in texts if text]


def xhtml_to_code(element: ET.Element) -> str:
    """
    Render the XHTML content of an `Example_Code` element as plain text, preserving document order.

    Lines are broken at `<br>` elements and at the boundaries of `<div>` elements, and each `<div>` with a left margin
    adds one level of indentation. Whitespace within the source is not significant, and is collapsed.
    """
    lines = []
    buffer = []

    def end_line(indent: int, keep_blank: bool = False):
        text = " ".join("".join(buffer).split())
        if text:
            lines.append(_CODE_INDENT * indent + text)
        elif keep_blank:
            lines.append("")
        buffer.clear()

    def walk(e: ET.Element, indent: int):
        buffer.append(e.text or "")
        for child in e:
            tag = _local_name(child)
            if tag == "br":
                end_line(indent, keep_blank=True)
            elif tag in ("div", "p"):
                end_line(indent)
                inner = indent + ("margin-left" in child.get("style", ""))
                walk(child, inner)
                end_line(inner)
            elif tag in ("ul", "ol", "table"):
                end_line(indent)
                block = (
                    _render_xhtml_table(child)
                    if tag == "table"
                    else _render_xhtml_list(child, ordered=tag == "ol")
                )
                lines.extend(_CODE_INDENT * indent + line for line in block.splitlines())
            elif tag == "img":
                buffer.append(_render_xhtml_inline(child))
            else:
                walk(child, indent)
            buffer.append(child.tail or "")

    walk(element, 0)
    end_line(0)
    return "\n".join(lines).strip("\n")


def xhtml_to_markdown(element: ET.Element) -> str:
    """
    Render the XHTML content of an element as Markdown, preserving document order.

    Paragraphs are separated by blank lines, `<ul>` becomes a `-` list, `<ol>` becomes a numbered list, `<table>`
    becomes a pipe table, `<br>` becomes a line break, `<img>` becomes an image link, and `<sup>` is prefixed with `^`.
    Other inline markup (e.g. `<b>`, `<i>`) is reduced to its text.
    """
    return "\n\n".join(_render_xhtml_blocks(element))


def _local_name(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _normalize_inline_text(text: str) -> str:
    lines = [" ".join(line.split()) for line in text.split(_LINE_BREAK)]
    return "\n".join(lines).strip("\n")


def _render_xhtml_inline(element: ET.Element) -> str:
    tag = _local_name(element)
    if tag == "br":
        return _LINE_BREAK
    if tag == "img":
        return f"![{element.get('alt', '')}]({element.get('src', '')})"

    parts = [element.text or ""]
    for child in element:
        parts.append(_render_xhtml_inline(child))
        parts.append(child.tail or "")
    text = "".join(parts)
    return f"^{text}" if tag == "sup" else text


def _render_xhtml_blocks(element: ET.Element) -> List[str]:
    blocks = []
    inline = []

    def flush():
        text = _normalize_inline_text("".join(inline))
        if text:
            blocks.append(text)
        inline.clear()

    inline.append(element.text or "")
    for child in element:
        tag = _local_name(child)
        if tag in ("ul", "ol"):
            flush()
            blocks.append(_render_xhtml_list(child, ordered=tag == "ol"))
        elif tag == "table":
            flush()
            blocks.append(_render_xhtml_table(child))
        elif tag in ("p", "div"):
            flush()
            blocks.extend(_render_xhtml_blocks(child))
        else:
            inline.append(_render_xhtml_inline(child))
        inline.append(child.tail or "")
    flush()
    return [block for block in blocks if block]


def _render_xhtml_list(element: ET.Element, ordered: bool) -> str:
    lines = []
    items = [child for child in element if _local_name(child) == "li"]
    for i, item in enumerate(items, start=1):
        marker = f"{i}. " if ordered else "- "
        body = "\n".join(_render_xhtml_blocks(item)).splitlines() or [""]
        lines.append(marker + body[0])
        lines.extend(" " * len(marker) + line for line in body[1:])
    return "\n".join(lines)


def _render_xhtml_table(element: ET.Element) -> str:
    def render_line(e: ET.Element) -> str:
        return " ".join(" ".join(_render_xhtml_blocks(e)).split())

    lines = []
    caption = next((e for e in element.iter() if _local_name(e) == "caption"), None)
    if caption is not None:
        lines.append(render_line(caption))

    rows = [e for e in element.iter() if _local_name(e) == "tr"]
    for i, row in enumerate(rows):
        cells = [e for e in row if _local_name(e) in ("th", "td")]
        texts = [render_line(cell).replace("|", "\\|") for cell in cells]
        lines.append("| " + " | ".join(texts) + " |")
        if i == 0:
            lines.append("| " + " | ".join("---" for _ in cells) + " |")
    return "\n".join(lines)
