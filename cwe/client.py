from typing import Optional
from cwe.util import JSONEncoder

import os
import cwe.parser
import json
import fnmatch
import io
import zipfile
import requests

DOWNLOAD_URL = 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'


def read_weakness_catalog(input_path: str):
    catalog = cwe.parser.parse_cwe_xml_file(input_path)
    return catalog


def download_weakness_catalog(output_path: Optional[str] = None, verify_tls: bool = True):
    """
    Download the latest version of the MITRE CWE XML file and save it to the specified output path.

    The XML file is distributed within a ZIP archive - this function will unpack the ZIP archive in memory, and write the XML file to the specified location.
    """
    response = requests.get(DOWNLOAD_URL, verify=verify_tls)
    response.raise_for_status()

    z = zipfile.ZipFile(io.BytesIO(response.content))
    internal_path = next(filter(lambda x: fnmatch.fnmatch(x, 'cwec_*.xml'), z.namelist()))

    if output_path is None:
        output_filename = os.path.basename(internal_path)
        output_path = output_filename

    with open(output_path, 'wb') as fp:
        fp.write(z.read(internal_path))


def convert(input_path: str, output_path: str, indent: int = 4):
    catalog = read_weakness_catalog(input_path)
    with open(output_path, 'w', encoding='utf-8') as fp:
        json.dump(catalog, fp, cls=JSONEncoder, sort_keys=True, indent=indent)
