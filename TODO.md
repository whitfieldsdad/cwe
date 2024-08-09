# TODO

- [ ] Parse references

```
...
{'@External_Reference_ID': 'REF-62', '@Section': 'Chapter 7, "Looping Constructs", Page 327'}
{'@External_Reference_ID': 'REF-62', '@Section': 'Chapter 7, "Looping Constructs", Page 327'}
{'@External_Reference_ID': 'REF-962', '@Section': 'ASCSM-CWE-835'}
{'@External_Reference_ID': 'REF-786'}
{'@External_Reference_ID': 'REF-787'}
...
```

- [ ] Parse descriptions in XHTML format

```json
{
    "@Detection_Method_ID": "DM-14",
    "Method": "Automated Static Analysis",
    "Description": "Automated static analysis, commonly referred to as Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect \"sources\" (origins of input) with \"sinks\" (destinations where the data interacts with external components, a lower layer such as the OS, etc.)",
    "Effectiveness": "High"
}
```

```json
{
    "Method": "Automated Static Analysis",
    "Description": {
        "xhtml:p": [
            "The external control or influence of filenames can often be detected using automated static analysis that models data flow within the product.",
            "Automated static analysis might not be able to recognize when proper input validation is being performed, leading to false positives - i.e., warnings that do not have any security consequences or require any code changes. If the program uses a customized input validation library, then some tools may allow the analyst to create custom signatures to detect usage of those routines."
        ]
    }
}
```

```json
{
    "Method": "Automated Static Analysis - Source Code",
    "Description": {
        "xhtml:p": "According to SOAR, the following detection techniques may be useful:",
        "xhtml:div": {
            "@style": "margin-left:1em;",
            "xhtml:div": "Highly cost effective:",
            "xhtml:ul": {
                "xhtml:li": [
                    "Source code Weakness Analyzer",
                    "Context-configured Source Code Weakness Analyzer"
                ]
            }
        }
    },
    "Effectiveness": "High"
}
```