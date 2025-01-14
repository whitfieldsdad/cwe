import datetime
import json
from typing import List, Union, Optional
from cwe.util import JSONEncoder
import dacite
import itertools
import xmltodict
from dataclasses import dataclass
import fnmatch
import io
import zipfile
import requests
import logging

logger = logging.getLogger(__name__)


DOWNLOAD_URL = 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'

HIGH = 'High'
MEDIUM = 'Medium'
LOW = 'Low'

INCOMPLETE = 'Incomplete'
DRAFT = 'Draft'
STABLE = 'Stable'
DEPRECATED = 'Deprecated'
OBSOLETE = 'Obsolete'


@dataclass()
class ExternalReference:
    id: str
    name: str
    publication_date: Optional[datetime.date]
    authors: List[str]
    url: Optional[str]

    
@dataclass()
class Consequence:
    scope: List[str]
    impact: List[str]
    note: Optional[str]
    

@dataclass()
class ModeOfIntroduction:
    phase: str
    note: Optional[str]


@dataclass()
class DetectionMethod:
    id: Optional[str]
    name: str
    description: Optional[str]
    effectiveness: Optional[str]
    

@dataclass()
class Weakness:
    id: str
    name: str
    abstraction: str
    structure: str
    status: str
    description: str
    extended_description: Optional[str]
    likelihood_of_exploitation: Optional[str]
    common_consequences: List[Consequence]
    modes_of_introduction: List[ModeOfIntroduction]
    detection_methods: List[DetectionMethod]


@dataclass()
class Category:
    id: str
    name: str
    description: str
    status: str
    
    def is_incomplete(self) -> bool:
        return self.status == INCOMPLETE

    def is_draft(self) -> bool:
        return self.status == DRAFT
    
    def is_stable(self) -> bool:
        return self.status == STABLE
    
    def is_deprecated(self) -> bool:
        return self.status == DEPRECATED
    
    def is_obsolete(self) -> bool:
        return self.status == OBSOLETE
    

@dataclass()
class Stakeholder:
    type: str
    description: Optional[str]
    
    def is_software_developers(self) -> bool:
        return self.type == 'Software Developers'
    
    def is_product_vendors(self) -> bool:
        return self.type == 'Product Vendors'
    
    def is_product_customers(self) -> bool:
        return self.type == 'Product Customers'    
    
    def is_assessment_tool_vendors(self) -> bool:
        return self.type == 'Assessment Tool Vendors'
    
    def is_educators(self) -> bool:
        return self.type == 'Educators'
    
    def is_hardware_designers(self) -> bool:
        return self.type == 'Hardware Designers'
    
    def is_academic_researchers(self) -> bool:
        return self.type == 'Academic Researchers'
    
    def is_applied_researchers(self) -> bool:
        return self.type == 'Applied Researchers'


@dataclass()
class Audience:
    stakeholders: List[Stakeholder]


@dataclass()
class View:
    id: str
    name: str
    type: str
    status: str
    objective: Optional[str]
    audience: Optional[Audience]
    cwe_ids: List[str]
    
    def is_obsolete(self) -> bool:
        return self.status == OBSOLETE


@dataclass()
class WeaknessCatalog:
    name: str
    version: str
    date: datetime.date
    weaknesses: List[Weakness]
    categories: List[Category]
    views: List[View]

    @property
    def consequences(self) -> List[Consequence]:
        consequences = set(itertools.chain.from_iterable(w.common_consequences for w in self.weaknesses))
        return sorted(consequences, key=lambda c: (c.scope, c.impact))
    
    @property
    def detection_methods(self) -> List[DetectionMethod]:
        detection_methods = set(itertools.chain.from_iterable(w.detection_methods for w in self.weaknesses))
        return sorted(detection_methods, key=lambda d: d.id)


def parse_cwe_xml_file(path: str) -> WeaknessCatalog:
    with open(path) as fp:
        data = xmltodict.parse(fp.read())

    weakness_catalog = parse_weakness_catalog(data['Weakness_Catalog'])
    return weakness_catalog


def parse_weakness_catalog(o: dict) -> WeaknessCatalog:
    weaknesses = list(map(parse_weakness, o['Weaknesses']['Weakness']))
    categories = list(map(parse_category, o['Categories']['Category']))
    views = list(map(parse_view, o['Views']['View']))

    data = {
        'name': o['@Name'],
        'version': o['@Version'],
        'date': datetime.datetime.fromisoformat(o['@Date']),
        'weaknesses': weaknesses,
        'categories': categories,
        'views': views,
    }
    return dacite.from_dict(WeaknessCatalog, data)


def parse_category(o: dict) -> Category:
    data = {
        'id': o['@ID'],
        'name': o['@Name'],
        'description': o['Summary'],
        'status': o['@Status']
    }
    return dacite.from_dict(Category, data)
    

def parse_weakness(o: dict) -> Weakness:
    common_consequences = []
    if 'Common_Consequences' in o:
        common_consequences = list(map(parse_consequence, ensure_list_of_dicts(o['Common_Consequences']['Consequence'])))
    
    modes_of_introduction = []
    if 'Modes_Of_Introduction' in o:
        for m in ensure_list_of_dicts(o['Modes_Of_Introduction']['Introduction']):
            modes_of_introduction.append(parse_mode_of_introduction(m))
    
    detection_methods = []
    if 'Detection_Methods' in o:
        for d in ensure_list_of_dicts(o['Detection_Methods']['Detection_Method']):
            detection_methods.append(parse_detection_method(d))
    
    # Some, but not all extended descriptions are encoded using HTML tags (e.g. <p>...</p>, <ol>...</ol>, <li>...</li>, etc.) - this is not supported.
    extended_description = None
    if 'Extended_Description' in o and isinstance(o['Extended_Description'], str):
        extended_description = o['Extended_Description']
        
    data = {
        'id': f"CWE-{o['@ID']}",
        'name': o['@Name'],
        'abstraction': o['@Abstraction'],
        'structure': o['@Structure'],
        'status': o['@Status'],
        'description': o['Description'],
        'extended_description': extended_description,
        'likelihood_of_exploitation': o.get('Likelihood_Of_Exploit'),
        'common_consequences': common_consequences,
        'modes_of_introduction': modes_of_introduction,
        'detection_methods': detection_methods
    }
    return dacite.from_dict(Weakness, data)


def parse_consequence(o: dict) -> Consequence:   
    scope = o['Scope']
    impact = o['Impact']
    note = None
    if 'Note' in o and isinstance(o['Note'], str):
        note = o['Note']
    
    data = {
        'scope': [scope] if isinstance(scope, str) else sorted(scope),
        'impact': [impact] if isinstance(impact, str) else sorted(impact),
        'note': note,
    }
    return dacite.from_dict(Consequence, data)
    
    
def parse_mode_of_introduction(o: dict) -> ModeOfIntroduction:
    note = None
    if 'Note' in o and isinstance(o['Note'], str):
        note = o['Note']
    
    data = {
        'phase': o['Phase'],
        'note': note,
    }
    return dacite.from_dict(ModeOfIntroduction, data)
    

def parse_detection_method(o: dict) -> DetectionMethod:
    description = None
    if 'Description' in o and isinstance(o['Description'], str):
        description = o['Description']
    
    data = {
        'id': o.get('@Detection_Method_ID'),
        'name': o['Method'],
        'description': description,
        'effectiveness': o.get('Effectiveness')
    }
    return dacite.from_dict(DetectionMethod, data)


def parse_view(o: dict) -> View:
    cwe_ids = set()
    if 'Members' in o:
        for m in o['Members']['Has_Member']:
            cwe_id = f"CWE-{m['CWE_ID']}"
            cwe_ids.add(cwe_id)
            
    objective = None
    if 'Objective' in o and isinstance(o['Objective'], str):
        objective = o['Objective']
    
    data = {
        'id': o['@ID'],
        'name': o['@Name'],
        'type': o['@Type'],
        'status': o['@Status'],
        'objective': objective,
        'audience': parse_audience(o['Audience']) if 'Audience' in o else None,
        'cwe_ids': sorted(cwe_ids)
    }
    return dacite.from_dict(View, data)


def parse_audience(o: dict) -> Audience:
    if isinstance(o['Stakeholder'], dict):
        stakeholders = [parse_stakeholder(o['Stakeholder'])]
    else:
        stakeholders = [parse_stakeholder(s) for s in o['Stakeholder']]
    
    data = {
        'stakeholders': stakeholders
    }
    return dacite.from_dict(Audience, data)


def parse_stakeholder(o: dict) -> Stakeholder:
    data = {
        'type': o['Type'],
        'description': o.get('Description')
    }
    return dacite.from_dict(Stakeholder, data)


def parse_external_reference(o: dict) -> ExternalReference:
    if 'Author' not in o:
        authors = []
    else:
        authors = [o['Author']] if isinstance(o['Author'], str) else sorted(o['Author'])
    
    keys = ['Publication_Year', 'Publication_Month', 'Publication_Day']
    if not all(k in o for k in keys):
        publication_date = None
    else:    
        publication_year = o['Publication_Year']
        publication_month = o['Publication_Month'].replace('-', '')
        publication_day = o['Publication_Day'].replace('-', '')
        publication_date = datetime.date(int(publication_year), int(publication_month), int(publication_day))
    
    data = {
        'id': o['@Reference_ID'],
        'name': o['Title'],
        'authors': authors,
        'publication_date': publication_date,
        'url': o.get('URL')
    }
    return dacite.from_dict(ExternalReference, data)


def download(output_path: str, verify_tls_certificate_chain: bool = True):
    """
    Download the latest version of the MITRE CWE XML file and save it to the specified output path.
    
    The XML file is distributed within a ZIP archive - this function will unpack the ZIP archive in memory, and write the XML file to the specified location.
    """
    response = requests.get(DOWNLOAD_URL, verify=verify_tls_certificate_chain)
    response.raise_for_status()
    
    z = zipfile.ZipFile(io.BytesIO(response.content))
    internal_path = next(filter(lambda x: fnmatch.fnmatch(x, 'cwec_*.xml'), z.namelist()))

    with open(output_path, 'w') as fp:
        fp.write(z.read(internal_path).decode('utf-8'))
        

def convert(input_path: str, output_path: str, indent: int = 4):
    catalog = parse_cwe_xml_file(input_path)
    with open(output_path, 'w') as fp:
        json.dump(catalog, fp, cls=JSONEncoder, sort_keys=True, indent=indent)


def ensure_list_of_dicts(rows: Union[dict, List[dict]]) -> List[dict]:
    """
    Ensure that the provided input is a list of dictionaries.
    """
    if isinstance(rows, dict):
        rows = [rows]
    assert all(isinstance(row, dict) for row in rows)
    return rows
