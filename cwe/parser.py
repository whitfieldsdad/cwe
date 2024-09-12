from typing import Optional, Union

import datetime
import dacite
from cwe import util
import logging

from cwe.types import WeaknessCatalog

logger = logging.getLogger(__name__)


def parse_weakness_catalog(o: dict) -> WeaknessCatalog:
    return dacite.from_dict(WeaknessCatalog, _parse_weakness_catalog(o))


def _parse_weakness_catalog(o: dict) -> dict:
    weaknesses = [_parse_weakness(w) for w in o['Weaknesses']['Weakness']]
    weaknesses = sorted(weaknesses, key=lambda x: _normalize_cwe_id(x['id']))

    return {
        'name': o['@Name'],
        'version': o['@Version'],
        'date': util.parse_date(o['@Date']),
        'weaknesses': weaknesses,
        'external_references': [_parse_external_reference(ref) for ref in o['External_References']['External_Reference']],
    }


def _normalize_cwe_id(v: str) -> str:
    prefix, suffix = v.split('-')
    suffix = suffix.zfill(4)
    return f'{prefix}-{suffix}'


def _parse_weakness(o: dict) -> dict:
    cwe_id = f"CWE-{o['@ID']}"

    related_weaknesses = []
    if 'Related_Weaknesses' in o:
        for w in util.as_dicts(o['Related_Weaknesses']['Related_Weakness']):
            related_weaknesses.append(_parse_related_weakness(w))

    # TODO: parse background details
    background_details = None
    if 'Background_Details' in o:
        background_details = o['Background_Details']['Background_Detail']
        if not isinstance(background_details, str):
            background_details = None

    modes_of_introduction = []
    if 'Modes_Of_Introduction' in o:
        for m in util.as_dicts(o['Modes_Of_Introduction']['Introduction']):
            modes_of_introduction.append({
                'phase': m['Phase'],
                'note': _parse_xml_str(m.get('Note')),
            })

    common_consequences = []
    if 'Common_Consequences' in o:
        common_consequences = [_parse_consequence(c) for c in util.as_dicts(o['Common_Consequences']['Consequence'])]

    detection_notes = []
    if 'Detection_Methods' in o:
        detection_notes = [_parse_detection_method(d) for d in util.as_dicts(o['Detection_Methods']['Detection_Method'])]

    # The observed examples section includes references to CVE IDs.
    observed_examples = []
    related_cves = []

    if 'Observed_Examples' in o:
        observed_examples = [d for d in util.as_dicts(o['Observed_Examples']['Observed_Example'], lowercase=True)]
        for eg in observed_examples:
            if eg['reference'].startswith('CVE-'):
                related_cves.append(eg['reference'])
        
        if related_cves:
            related_cves = sorted(related_cves)

    mitigations = []
    if 'Potential_Mitigations' in o:
        mitigations = [_parse_mitigation(m) for m in util.as_dicts(o['Potential_Mitigations']['Mitigation'])]

    alternate_terms = []
    if 'Alternate_Terms' in o:
        alternate_terms = sorted({t['Term'] for t in util.as_dicts(o['Alternate_Terms']['Alternate_Term'])})

    taxonomy_mappings = []
    if 'Taxonomy_Mappings' in o:
        taxonomy_mappings = [_parse_taxonomy_mapping(t) for t in util.as_dicts(o['Taxonomy_Mappings']['Taxonomy_Mapping'])]

    related_attack_patterns = []
    if 'Related_Attack_Patterns' in o:
        related_attack_patterns = [f"CAPEC-{ap['@CAPEC_ID']}" for ap in util.as_dicts(o['Related_Attack_Patterns']['Related_Attack_Pattern'])]

    return {
        'id': cwe_id,
        'name': o['@Name'],
        'alternate_terms': alternate_terms,
        'abstraction': o['@Abstraction'],
        'structure': o['@Structure'],
        'status': o['@Status'],
        'description': _parse_xml_str(o['Description']),
        'extended_description': _parse_xml_str(o.get('Extended_Description')),
        'related_weaknesses': related_weaknesses,
        'background_details': background_details,
        'common_consequences': common_consequences,
        'content_history': _parse_content_history(o['Content_History']),
        'likelihood_of_exploit': o.get('Likelihood_Of_Exploit'),
        'detection_notes': detection_notes,
        'modes_of_introduction': modes_of_introduction,
        'observed_examples': observed_examples,
        'mapping_notes': _parse_mapping_notes(o['Mapping_Notes']),
        'mitigations': mitigations,
        'taxonomy_mappings': taxonomy_mappings,
        'related_attack_patterns': related_attack_patterns,
    }


def _parse_taxonomy_mapping(o: dict) -> dict:
    return {
        'taxonomy_name': o['@Taxonomy_Name'],
        'entry_id': o.get('Entry_ID'),
        'entry_name': o.get('Entry_Name'),
    }


def _parse_external_reference(o: dict) -> dict:
    """
    Example input (XML):
    
    <External_Reference Reference_ID="REF-1447">
        <Author>Cybersecurity and Infrastructure Security Agency</Author>
        <Title>Secure by Design Alert: Eliminating SQL Injection Vulnerabilities in Software</Title>
        <Publication_Year>2024</Publication_Year>
        <Publication_Month>--03</Publication_Month>
        <Publication_Day>---25</Publication_Day>
        <URL>https://www.cisa.gov/resources-tools/resources/secure-design-alert-eliminating-sql-injection-vulnerabilities-software</URL>
        <URL_Date>2024-07-14</URL_Date>
    </External_Reference>

    Example output:

    {
        'id': 'REF-1447',
        'author': 'Cybersecurity and Infrastructure Security Agency',
        'title': 'Secure by Design Alert: Eliminating SQL Injection Vulnerabilities in Software',
        'date': '2024-03-25',
        'url': 'https://www.cisa.gov/resources-tools/resources/secure-design-alert-eliminating-sql-injection-vulnerabilities-software',
    }
    """
    publication_date = publication_year = publication_month = publication_day = None
    if 'Publication_Year' in o:
        publication_year = int(o['Publication_Year'])

    if 'Publication_Month' in o:
        publication_month = int(o['Publication_Month'].replace('-', ''))
    
    if 'Publication_Day' in o:
        publication_day = int(o['Publication_Day'].replace('-', ''))

    if all([publication_year, publication_month, publication_day]):
        publication_date = datetime.date(publication_year, publication_month, publication_day)

    return {
        'id': o['@Reference_ID'],
        'title': o['Title'],
        'publication_year': publication_year,
        'publication_month': publication_month,
        'publication_day': publication_day,
        'publication_date': publication_date,
        'publisher': o.get('Publisher'),
        'url': o.get('URL'),
        'url_date': util.parse_date(o.get('URL_Date')),
    }


def _parse_mapping_notes(o: dict) -> dict:
    reasons = []
    if 'Reasons' in o:
        reasons = [r['@Type'] for r in util.as_dicts(o['Reasons']['Reason'])]

    return {
        'usage': o['Usage'],
        'rationale': o['Rationale'],
        'comments': _parse_xml_str(o['Comments']),
        'reasons': reasons,
    }

def _parse_detection_method(o: dict) -> dict:
    return {
        'id': o.get('@Detection_Method_ID'),
        'method': o['Method'],
        'effectiveness': o.get('Effectiveness'),
        'description': _parse_xml_str(o['Description']),
    }


def _parse_mitigation(o: dict) -> dict:
    phases = []
    if 'Phase' in o:
        phases = util.as_list(o['Phase'])

    return {
        'id': o.get('@Mitigation_ID'),
        'phases': phases,
        'strategy': o.get('Strategy'),
        'description': _parse_xml_str(o['Description']),
        'effectiveness': o.get('Effectiveness'),
        'effectiveness_notes': _parse_xml_str(o.get('Effectiveness_Notes')),
    }


def _parse_related_weakness(o: dict) -> dict:
    return {
        'id': f'CWE-{o["@CWE_ID"]}',
        'nature': o['@Nature'],
        'view_id': o['@View_ID'],
        'ordinal': o.get('@Ordinal'),
    }


def _parse_content_history(o: dict) -> dict:
    modifications = []
    if 'Modification' in o:
        modifications = [_parse_modification(m) for m in util.as_dicts(o['Modification'])]

    return {
        'submission': _parse_submission(o['Submission']),
        'modifications': modifications,
    }


def _parse_submission(o: dict) -> dict:
    return {
        'name': o.get('Submission_Name'),
        'organization': o.get('Submission_Organization'),
        'date': util.parse_date(o['Submission_Date']),
        'release_date': util.parse_date(o['Submission_ReleaseDate']),
        'version': o['Submission_Version'],
    }


def _parse_modification(o: dict) -> dict:
    return {
        'name': o.get('Modification_Name'),
        'organization': o.get('Modification_Organization'),
        'date': util.parse_date(o['Modification_Date']),
        'comment': o.get('Modification_Comment'),
    }


def _parse_consequence(o: dict) -> dict:
    return {
        'scope': util.as_list(o['Scope']),
        'impact': util.as_list(o['Impact']),
        'note': _parse_xml_str(o.get('Note')),
    }


# TODO
def _parse_xml_str(o: Optional[Union[str, dict]]) -> Optional[str]:
    if o is not None:
        if isinstance(o, str):
            return o
