from typing import Optional
from cwe.types import WeaknessCatalog
from cwe.util import JSONEncoder

import os
import cwe.parser
import json
import fnmatch
import io
import zipfile
import requests

DOWNLOAD_URL = 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'


def get_weakness_catalog(output_path: Optional[str] = None, verify_tls: bool = True) -> WeaknessCatalog:
    if output_path:
        download_weakness_catalog(output_path, verify_tls=verify_tls)
        return read_weakness_catalog(output_path)
    else:
        data = read_remote_weakness_catalog_xml_file(verify_tls=verify_tls)
        with io.StringIO(data) as fp:
            return cwe.parser.parse_cwe_xml_file(fp)


def read_weakness_catalog(input_path: str):
    catalog = cwe.parser.parse_cwe_xml_file(input_path)
    return catalog


def read_remote_weakness_catalog_xml_file(verify_tls: bool = True) -> str:
    """
    Downloads the ZIP file containing the latest MITRE CWE XML file, 
    unpacks the archive in-memory, and returns the contents of the XML file as a string.
    """
    response = requests.get(DOWNLOAD_URL, verify=verify_tls)
    response.raise_for_status()
    
    z = zipfile.ZipFile(io.BytesIO(response.content))
    path = next(filter(lambda x: fnmatch.fnmatch(x, 'cwec_*.xml'), z.namelist()))
    return z.read(path).decode('utf-8')


def download_weakness_catalog(output_path: str, verify_tls: bool = True):
    """
    Downloads the latest MITRE CWE XML file and saves it to the specified output path.
    """
    data = read_remote_weakness_catalog_xml_file(verify_tls=verify_tls)
    with open(output_path, 'w', encoding='utf-8') as fp:
        fp.write(data)


def convert_from_xml_to_json(input_path: str, output_path: str, indent: int = 4):
    catalog = read_weakness_catalog(input_path)
    with open(output_path, 'w', encoding='utf-8') as fp:
        json.dump(catalog, fp, cls=JSONEncoder, sort_keys=True, indent=indent)
