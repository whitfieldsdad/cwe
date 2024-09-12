import tempfile
import os


DOWNLOAD_URL = 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'
DOWNLOAD_PATH = os.path.join(tempfile.gettempdir(), 'bd49ef18-12b8-415e-a986-a876b2329fc1', 'cwec.xml')

DEFAULT_EDGE_LABEL_KEY = 'nature'
