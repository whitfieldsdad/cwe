from dataclasses import dataclass
import fnmatch
import os
import tempfile
from typing import Dict, Iterator, List

import requests, zipfile, io
import logging
import xmltodict
from cwe import parser, util

from cwe.constants import DOWNLOAD_PATH, DOWNLOAD_URL
from cwe.types import DetectionMethod, Mitigation, Weakness, WeaknessCatalog

logger = logging.getLogger(__name__)


@dataclass()
class CWE:
    url: str = DOWNLOAD_URL
    path: str = DOWNLOAD_PATH

    def download(self):
        if not os.path.exists(self.path):
            os.makedirs(os.path.dirname(self.path), exist_ok=True)

        response = requests.get(DOWNLOAD_URL, verify=False)
        response.raise_for_status()
        
        z = zipfile.ZipFile(io.BytesIO(response.content))
        internal_path = next(filter(lambda x: fnmatch.fnmatch(x, 'cwec_*.xml'), z.namelist()))

        if not output_path:
            output_path = tempfile.mkstemp(suffix='.xml')
        
        with open(output_path, 'w') as output_file:
            output_file.write(z.read(internal_path).decode('utf-8'))  

    def get_weakness_catalog(self) -> WeaknessCatalog:
        if not os.path.exists(self.path):
            self.download()

        with open(self.path, 'r') as f:
            data = xmltodict.parse(f.read())
            return parser.parse_weakness_catalog(data['Weakness_Catalog'])

    def iter_weaknesses(self) -> Iterator[Weakness]:
        catalog = self.get_weakness_catalog()
        yield from catalog.weaknesses
    
    def iter_detection_methods(self) -> Iterator[DetectionMethod]:
        def gen():
            seen = set()
            for weakness in self.iter_weaknesses():
                for detection_method in weakness.detection_methods:
                    if detection_method.id not in seen:
                        seen.add(detection_method.id)
                        yield detection_method
        
        yield from sorted(gen(), key=lambda x: x.id)

    def iter_mitigations(self) -> Iterator[Mitigation]:
        def gen():
            seen = set()
            for weakness in self.iter_weaknesses():
                for mitigation in weakness.mitigations:
                    if mitigation.id not in seen:
                        seen.add(mitigation.id)
                        yield mitigation
        
        yield from sorted(gen(), key=lambda x: x.id)

    def get_cwe_ids(self) -> List[str]:
        return sorted({w.id for w in self.iter_weaknesses()})

    def get_cwe_id_to_cve_id_map(self) -> Dict[str, List[str]]:
        m = {}
        for cwe in self.iter_weaknesses():
            for cve_id in cwe.get_related_cve_ids():
                if cve_id in m:
                    m[cve_id] = sorted(m[cve_id] + [cwe.id])
                else:
                    m[cve_id] = [cwe.id]
        return dict(m)

    def get_cve_id_to_cwe_id_map(self) -> Dict[str, List[str]]:
        m = self.get_cwe_id_to_cve_id_map()
        return util.inv_1_to_m(m)
