# Common Weakness Enumeration (CWE) parser

This is a parser for the MITRE [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) [dataset](https://cwe.mitre.org/data/downloads.html) that allows you to convert the [XML file](data/cwec_v5.0.xml) into a [JSON](data/mitre-cwe.json) [representation](docs/mitre-cwe.schema.json.png) ([schema](docs/mitre-cwe.schema.json)).

## Features

- [Download the latest version of the MITRE CWE weakness catalog](#download-latest-version-of-the-mitre-cwe-xml-file)
- Extract weaknesses, groupings, views, external references, and other related entities (e.g. detection methods and mitigations related to a particular weakness, taxonomy mappings, etc.)
- [Extract mappings between CWE weaknesses and CAPEC techniques](#extract-mappings-between-cwe-weaknesses-and-capec-techniques)
- [Extract mappings between CWE weaknesses and CVE vulnerabilities](#extract-mappings-between-cwe-weaknesses-and-cve-vulnerabilities)

## Caveats

- Weakness, grouping, and view IDs are integers stored in string values (e.g. `CWE-416` is `416`)

## Usage

### Python

#### Download latest version of the MITRE CWE XML file

The MITRE CWE database is distributed as a ZIP file containing a single XML file. 

The `download` function unzips the file in memory and saves the XML to the specified output path.

If no output path is specified, the name of the XML file within the ZIP file will be used (e.g. `cwec_v5.0.xml`).

To download the latest XML file to the current directory with the default filename:

```python
import cwe.client

cwe.client.download()
```

To specify a download filename:

```python
import cwe.client

output_path = 'mitre-cwe.xml'

cwe.client.download(output_path=output_path)
```

> You can disable TLS verification by passing `verify_tls=False` to the `download` function.

