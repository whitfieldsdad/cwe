import collections
from dataclasses import dataclass
import fnmatch
import os
import tempfile
from typing import Any, Iterator, List

import requests, zipfile, io
import logging
import xmltodict

logger = logging.getLogger(__name__)

DOWNLOAD_URL = 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'
DEFAULT_PATH = os.path.join(tempfile.gettempdir(), 'bd49ef18-12b8-415e-a986-a876b2329fc1', 'cwec.xml')


@dataclass()
class CWE:
    url: str = DOWNLOAD_URL
    path: str = DEFAULT_PATH

    def iter_weaknesses(self) -> Iterator[dict]:
        if not os.path.exists(self.path):
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            download_cwe_data(self.path)

        with open(self.path, 'r') as f:
            data = xmltodict.parse(f.read())
            for o in data['Weakness_Catalog']['Weaknesses']['Weakness']:
                yield parse_weakness(o)
    
    def get_weakness_scopes(self) -> List[str]:
        scopes = set()
        for cwe in self.iter_weaknesses():
            for consequence in cwe['common_consequences']:
                for scope in consequence['scope']:
                    scopes.add(scope)
        return sorted(scopes)
    
    def get_weakness_impacts(self) -> List[str]:
        scopes = set()
        for cwe in self.iter_weaknesses():
            for consequence in cwe['common_consequences']:
                for scope in consequence['impact']:
                    scopes.add(scope)
        return sorted(scopes)

    def get_cwe_id_to_cve_id_mappings(self) -> dict:
        cwe_to_cve = collections.defaultdict(list)
        for cwe in self.iter_weaknesses():
            cwe_id = cwe['id']
            for cve_id in cwe['related_cve_ids']:
                cwe_to_cve[cwe_id].append(cve_id)
        return dict(cwe_to_cve)

    def get_cve_id_to_cwe_id_mappings(self) -> dict:
        cwe_to_cve = self.get_cwe_id_to_cve_id_mappings()
        cve_to_cwe = collections.defaultdict(list)
        for cwe_id, cve_ids in cwe_to_cve.items():
            for cve_id in cve_ids:
                cve_to_cwe[cve_id].append(cwe_id)
        return dict(cve_to_cwe)
    
    def get_cwe_id_to_detection_id_mappings(self) -> dict:
        cwe_to_detection_id = collections.defaultdict(list)
        for cwe in self.iter_weaknesses():
            cwe_id = cwe['id']
            for detection in cwe['detection_methods']:
                detection_id = detection['id']
                if detection_id:
                    cwe_to_detection_id[cwe_id].append(detection_id)
        return dict(cwe_to_detection_id)
    
    def get_detection_id_to_cwe_id_mappings(self) -> dict:
        cwe_to_detection_id = self.get_cwe_id_to_detection_id_mappings()
        detection_id_to_cwe = collections.defaultdict(list)
        for cwe_id, detection_ids in cwe_to_detection_id.items():
            for detection_id in detection_ids:
                detection_id_to_cwe[detection_id].append(cwe_id)
        return dict(detection_id_to_cwe)
    
    def get_cwe_id_to_mitigation_id_mappings(self) -> dict:
        cwe_to_mitigation_id = collections.defaultdict(list)
        for cwe in self.iter_weaknesses():
            cwe_id = cwe['id']
            for mitigation in cwe['mitigations']:
                mitigation_id = mitigation['id']
                if mitigation_id:
                    cwe_to_mitigation_id[cwe_id].append(mitigation_id)
        return dict(cwe_to_mitigation_id)
    
    def get_mitigation_id_to_cwe_id_mappings(self) -> dict:
        cwe_to_mitigation_id = self.get_cwe_id_to_mitigation_id_mappings()
        mitigation_id_to_cwe = collections.defaultdict(list)
        for cwe_id, mitigation_ids in cwe_to_mitigation_id.items():
            for mitigation_id in mitigation_ids:
                mitigation_id_to_cwe[mitigation_id].append(cwe_id)
        return dict(mitigation_id_to_cwe)
    
    def get_cve_id_to_mitigation_id_mappings(self) -> dict:
        """
        Warning: experimental
        """
        cve_to_mitigation_id = collections.defaultdict(list)
        for cwe in self.iter_weaknesses():
            for cve_id in cwe['related_cve_ids']:
                for mitigation in cwe['mitigations']:
                    mitigation_id = mitigation['id']
                    if mitigation_id:
                        cve_to_mitigation_id[cve_id].append(mitigation_id)
        return dict(cve_to_mitigation_id)
    
    def get_mitigation_id_to_cve_id_mappings(self) -> dict:
        """
        Warning: experimental
        """
        cve_to_mitigation_id = self.get_cve_id_to_mitigation_id_mappings()
        mitigation_id_to_cve = collections.defaultdict(list)
        for cve_id, mitigation_ids in cve_to_mitigation_id.items():
            for mitigation_id in mitigation_ids:
                mitigation_id_to_cve[mitigation_id].append(cve_id)
        return dict(mitigation_id_to_cve)
    
    def get_cve_id_to_detection_id_mappings(self) -> dict:
        """
        Warning: experimental
        """
        cve_to_detection_id = collections.defaultdict(list)
        for cwe in self.iter_weaknesses():
            for cve_id in cwe['related_cve_ids']:
                for detection in cwe['detection_methods']:
                    detection_id = detection['id']
                    if detection_id:
                        cve_to_detection_id[cve_id].append(detection_id)
        return dict(cve_to_detection_id)
    
    def get_detection_id_to_cve_id_mappings(self) -> dict:
        """
        Warning: experimental
        """
        cve_to_detection_id = self.get_cve_id_to_detection_id_mappings()
        detection_id_to_cve = collections.defaultdict(list)
        for cve_id, detection_ids in cve_to_detection_id.items():
            for detection_id in detection_ids:
                detection_id_to_cve[detection_id].append(cve_id)
        return dict(detection_id_to_cve)


def parse_weakness(o: dict) -> dict:
    cwe_id = f"CWE-{o['@ID']}"

    extended_description = o.get('Extended_Description')
    if extended_description and not isinstance(extended_description, str):
        extended_description = None

    # Common consequences
    common_consequences = []
    if 'Common_Consequences' in o:
        c = o['Common_Consequences']['Consequence']
        cs = c if isinstance(c, list) else [c]
        for c in cs:
            scope = [c['Scope']] if isinstance(c['Scope'], str) else c['Scope']
            impact = [c['Impact']] if isinstance(c['Impact'], str) else c['Impact']
            note = c.get('Note')
            common_consequences.append({
                'scope': scope,
                'impact': impact,
                'note': note,
            })

    # Detection methods
    detection_methods = []
    if 'Detection_Methods' in o:
        d = o['Detection_Methods']['Detection_Method']
        ds = d if isinstance(d, list) else [d]
        for d in ds:
            description = d.get('Description')
            if description and not isinstance(description, str):
                description = None

            detection_methods.append({
                'id': d.get('@Detection_Method_ID'),
                'method': d['Method'],
                'effectiveness': d.get('Effectiveness'),
                'description': description,
            })

    # Mitigations
    mitigations = []
    if 'Potential_Mitigations' in o:
        m = o['Potential_Mitigations']['Mitigation']
        ms = m if isinstance(m, list) else [m]
        for m in ms:
            description = m.get('Description')
            if description and not isinstance(description, str):
                description = None

            mitigations.append({
                'id': m.get('@Mitigation_ID'),
                'phase': m.get('Phase'),
                'strategy': m.get('Strategy'),
                'description': description,
            })
    
    # Modes of introduction
    modes_of_introduction = []
    if 'Modes_Of_Introduction' in o:
        m = o['Modes_Of_Introduction']['Introduction']
        ms = m if isinstance(m, list) else [m]
        for m in ms:
            modes_of_introduction.append({
                'phase': m['Phase'],
                'note': m.get('Note'),
            })

    # Background details
    background_details = []
    if 'Background_Details' in o:
        b = o['Background_Details']['Background_Detail']
        if isinstance(b, str):
            background_details.append(b)

    # Observed examples
    observed_examples = []
    related_cve_ids = []

    if 'Observed_Examples' in o:
        e = o['Observed_Examples']['Observed_Example']
        es = e if isinstance(e, list) else [e]
        for e in es:
            if fnmatch.fnmatch(e['Reference'], 'CVE-*'):
                related_cve_ids.append(e['Reference'])

            observed_examples.append({
                'reference': e['Reference'],
                'description': e['Description'],
                'link': e['Link'],
            })

    # Mapping notes
    mapping_notes = None
    if 'Mapping_Notes' in o:
        mapping_notes = parse_weakness_mapping_notes(o['Mapping_Notes'])

    # Version history
    content_history = o['Content_History']
    s = content_history['Submission']

    submission = {
        'name': s.get('Submission_Name'),
        'organization': s.get('Submission_Organization'),
        'date': s['Submission_Date'],
        'release_date': s['Submission_ReleaseDate'],
        'release_version': s['Submission_Version'],
    }
    created = submission['date']

    last_updated = None
    modifications = content_history.get('Modification')
    if modifications:
        modifications = list(map(parse_modification, as_dicts(modifications)))
        last_updated = max([m['date'] for m in modifications])

    return {
        'id': cwe_id,
        'name': o['@Name'],
        'abstraction': o['@Abstraction'],
        'structure': o['@Structure'],
        'status': o['@Status'],
        'description': o['Description'],
        'extended_description': extended_description,
        'created': created,
        'last_updated': last_updated,
        'history': {
            'submission': submission,
            'modifications': modifications,
        },
        'related_weaknesses': parse_related_weaknesses(o),
        'related_cve_ids': sorted(related_cve_ids),
        'likelihood_of_exploitation': o.get('Likelihood_Of_Exploit'),
        'common_consequences': common_consequences,
        'detection_methods': detection_methods,
        'mitigations': mitigations,
        'modes_of_introduction': modes_of_introduction,
        'background_details': background_details,
        'observed_examples': observed_examples,
        'mapping_notes': mapping_notes,
    }


def parse_modification(o: dict) -> dict:
    return {
        'name': o.get('Modification_Name'),
        'organization': o.get('Modification_Organization'),
        'date': o['Modification_Date'],
        'comment': o.get('Modification_Comment'),
    }

def parse_weakness_mapping_notes(o: dict) -> dict:
    reasons = o['Reasons']['Reason']
    if not isinstance(reasons, list):
        reasons = [reasons]
    
    reasons = [r['@Type'] for r in reasons]
    
    return {
        'usage': o['Usage'],
        'rationale': o['Rationale'],
        'comments': o['Comments'],
        'reasons': reasons,
    }



def parse_related_weaknesses(o: dict) -> List[dict]:
    weaknesses = []
    related = o.get('Related_Weaknesses')
    if not related:
        return weaknesses
    
    related = related['Related_Weakness']
    if isinstance(related, dict):
        related = [related]

    for r in related:
        w = {
            'id': f'CWE-{r["@CWE_ID"]}',
            'nature': r['@Nature'],
        }
        weaknesses.append(w)
    return weaknesses


def download_cwe_data(output_path: str, url: str = DOWNLOAD_URL):
    response = requests.get(DOWNLOAD_URL, verify=False)
    response.raise_for_status()
     
    z = zipfile.ZipFile(io.BytesIO(response.content))
    internal_path = next(filter(lambda x: fnmatch.fnmatch(x, 'cwec_*.xml'), z.namelist()))

    if not output_path:
        output_path = tempfile.mkstemp(suffix='.xml')
    
    with open(output_path, 'w') as f:
        f.write(z.read(internal_path).decode('utf-8'))


def as_dicts(o: Any, lowercase: bool = False) -> List[dict]:
    if isinstance(o, dict):
        o = [o]
    elif isinstance(o, list) and all(isinstance(x, dict) for x in o):
        o = o
    else:
        raise ValueError("Expected a dict or a list of dicts")

    if lowercase:
        o = [lowercase_dict_keys(x) for x in o]
    return o


def lowercase_dict_keys(d: dict) -> dict:
    return {k.lower(): v for k, v in d.items()}
