# Development guide

## Usage

To install the project:

```shell
poetry install
```

To enter a virtual environment containing the project's dependencies<sub>1</sub>:

```shell
poetry shell
```

<sub>1. The `poetry shell` command has been moved to a [plugin](https://github.com/python-poetry/poetry-plugin-shell). You can add the required plugin to `poetry` as follows: `poetry self add poetry-plugin-shell`.</sub>

## Parser

### Data types

#### Weaknesses

Example weakness:

```json
{
    "@ID": "416",
    "@Name": "Use After Free",
    "@Abstraction": "Variant",
    "@Structure": "Simple",
    "@Status": "Stable",
    "@Diagram": "/data/images/CWE-416-Diagram.png",
    "Description": "The product reuses or references memory after it has been freed. At some point afterward, the memory may be allocated again and saved in another pointer, while the original pointer references a location somewhere within the new allocation. Any operations using the original pointer are no longer valid because the memory \"belongs\" to the code thatoperates on the new pointer.",
    "Related_Weaknesses": {
        "Related_Weakness": [
            {
                "@Nature": "ChildOf",
                "@CWE_ID": "825",
                "@View_ID": "1000",
                "@Ordinal": "Primary"
            },
            {
                "@Nature": "ChildOf",
                "@CWE_ID": "672",
                "@View_ID": "1003",
                "@Ordinal": "Primary"
            },
            {
                "@Nature": "ChildOf",
                "@CWE_ID": "672",
                "@View_ID": "1305",
                "@Ordinal": "Primary"
            },
            {
                "@Nature": "ChildOf",
                "@CWE_ID": "672",
                "@View_ID": "1340",
                "@Ordinal": "Primary"
            },
            {
                "@Nature": "CanPrecede",
                "@CWE_ID": "120",
                "@View_ID": "1000"
            },
            {
                "@Nature": "CanPrecede",
                "@CWE_ID": "123",
                "@View_ID": "1000"
            }
        ]
    },
    "Weakness_Ordinalities": {
        "Weakness_Ordinality": {
            "Ordinality": "Resultant",
            "Description": "If the product accesses a previously-freed pointer, then it means that a separate weakness or error already occurred previously, such as a race condition, an unexpected or poorly handled error condition, confusion over which part of the program is responsible for freeing the memory,performing the free too soon, etc."
        }
    },
    "Applicable_Platforms": {
        "Language": [
            {
                "@Class": "Memory-Unsafe",
                "@Prevalence": "Often"
            },
            {
                "@Name": "C",
                "@Prevalence": "Often"
            },
            {
                "@Name": "C++",
                "@Prevalence": "Often"
            }
        ]
    },
    "Alternate_Terms": {
        "Alternate_Term": [
            {
                "Term": "Dangling pointer",
                "Description": "a pointer that no longer points to valid memory, often after it has been freed"
            },
            {
                "Term": "UAF",
                "Description": "commonly used acronym for Use After Free"
            },
            {
                "Term": "Use-After-Free"
            }
        ]
    },
    "Modes_Of_Introduction": {
        "Introduction": {
            "Phase": "Implementation"
        }
    },
    "Likelihood_Of_Exploit": "High",
    "Common_Consequences": {
        "Consequence": [
            {
                "Scope": "Integrity",
                "Impact": "Modify Memory",
                "Note": "The use of previously freed memory may corrupt valid data, if the memory area in question has been allocated and used properly elsewhere."
            },
            {
                "Scope": "Availability",
                "Impact": "DoS: Crash, Exit, or Restart",
                "Note": "If chunk consolidation occurs after the use of previously freed data, the process may crash when invalid data is used as chunk information."
            },
            {
                "Scope": "Confidentiality",
                "Impact": "Read Memory",
                "Note": "Read operations on freed memory can sometimes leak sensitive information instead of causing a crash"
            },
            {
                "Scope": [
                    "Integrity",
                    "Confidentiality",
                    "Availability"
                ],
                "Impact": "Execute Unauthorized Code or Commands",
                "Note": "If malicious data is entered before chunk consolidation can take place, it may be possible to take advantage of a write-what-where primitive to execute arbitrary code. If the newly allocated data happens to hold a class, in C++ for example, various function pointers may be scattered within the heap data. If one of these function pointers is overwritten with an address to valid shellcode, execution of arbitrary code can be achieved."
            }
        ]
    },
    "Detection_Methods": {
        "Detection_Method": [
            {
                "@Detection_Method_ID": "DM-13",
                "Method": "Fuzzing",
                "Description": "Fuzz testing (fuzzing) is a powerful technique for generating large numbers of diverse inputs - either randomly or algorithmically - and dynamically invoking the code with those inputs. Even with random inputs, it is often capable of generating unexpected results such as crashes, memory corruption, or resource consumption. Fuzzing effectively produces repeatable test cases that clearly indicate bugs, which helps developers to diagnose the issues.",
                "Effectiveness": "High"
            },
            {
                "@Detection_Method_ID": "DM-14",
                "Method": "Automated Static Analysis",
                "Description": "Automated static analysis, commonly referred toas Static Application Security Testing (SAST), can find some instances of this weakness by analyzing source code (or binary/compiled code) without having to execute it. Typically, this is done by building a model of data flow and control flow, then searching for potentially-vulnerable patterns that connect \"sources\" (origins of input) with \"sinks\" (destinations where the data interacts with external components, a lower layer such as the OS, etc.)",
                "Effectiveness": "High"
            },
            {
                "@Detection_Method_ID": "DM-15",
                "Method": "Automated Dynamic Analysis",
                "Description": "Use tools that are integrated during\n\t     compilation to insert runtime error-checking mechanisms\n\t     related to memory safety errors, such as AddressSanitizer\n\t     (ASan) for C/C++ [REF-1518].",
                "Effectiveness": "Moderate",
                "Effectiveness_Notes": "Crafted inputs are necessary to\n\t     reach the code containing the error, such as generated\n\t     by fuzzers.  Also, these tools may reduce performance,\n\t     and they only report the error condition - not the\n\t original mistake that led to the\n\t     error."
            }
        ]
    },
    "Potential_Mitigations": {
        "Mitigation": [
            {
                "Phase": "Architecture and Design",
                "Strategy": "Language Selection",
                "Description": "Choose a language that provides automatic memory management."
            },
            {
                "Phase": "Implementation",
                "Strategy": "Attack Surface Reduction",
                "Description": "When freeing pointers, be sure to set them to NULL once they are freed. However, the utilization of multiple or complex data structures may lower the usefulness of this strategy.",
                "Effectiveness": "Defense in Depth",
                "Effectiveness_Notes": "If a bug causes an attempted access of this pointer, then a NULL dereference could still lead to a crash or other unexpected behavior, but it will reduce or eliminate the risk of code execution."
            }
        ]
    },
    "Demonstrative_Examples": {
        "Demonstrative_Example": [
            {
                "Intro_Text": "The following example demonstrates the weakness.",
                "Example_Code": {
                    "@Nature": "Bad",
                    "@Language": "C",
                    "xhtml:div": {
                        "xhtml:br": [
                            null,
                            null,
                            null,
                            null
                        ],
                        "xhtml:div": {
                            "@style": "margin-left:1em;",
                            "xhtml:br": [
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null
                            ],
                            "#text": "char *buf1R1;char *buf2R1;char *buf2R2;char *buf3R2;buf1R1 = (char *) malloc(BUFSIZER1);buf2R1 = (char *) malloc(BUFSIZER1);free(buf2R1);buf2R2 = (char *) malloc(BUFSIZER2);buf3R2 = (char *) malloc(BUFSIZER2);strncpy(buf2R1, argv[1], BUFSIZER1-1);free(buf1R1);free(buf2R2);free(buf3R2);"
                        },
                        "#text": "#include <stdio.h>#include <unistd.h>#define BUFSIZER1 512#define BUFSIZER2 ((BUFSIZER1/2) - 8)int main(int argc, char **argv) {}"
                    }
                }
            },
            {
                "Intro_Text": "The following code illustrates a use after free error:",
                "Example_Code": {
                    "@Nature": "Bad",
                    "@Language": "C",
                    "xhtml:div": {
                        "xhtml:br": [
                            null,
                            null,
                            null
                        ],
                        "xhtml:div": [
                            {
                                "@style": "margin-left:1em;",
                                "xhtml:br": null,
                                "#text": "abrt = 1;free(ptr);"
                            },
                            {
                                "@style": "margin-left:1em;",
                                "#text": "logError(\"operation aborted before commit\", ptr);"
                            }
                        ],
                        "#text": "char* ptr = (char*)malloc (SIZE);if (err) {}...if (abrt) {}"
                    }
                },
                "Body_Text": "When an error occurs, the pointer is immediately freed. However, this pointer is laterincorrectly used in the logError function."
            }
        ]
    },
    "Observed_Examples": {
        "Observed_Example": [
            {
                "Reference": "CVE-2023-38160",
                "Description": "TCP/IP code for an OS has a use-after-free that can leak heap memory contents",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2023-38160"
            },
            {
                "Reference": "CVE-2023-5447",
                "Description": "Chain: missing lock check (CWE-414) leads to Use-After-Free (CWE-416)",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2023-5447"
            },
            {
                "Reference": "CVE-2022-20141",
                "Description": "Chain: an operating system kernel has insufficient resource locking (CWE-413) leading to a use after free (CWE-416).",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2022-20141"
            },
            {
                "Reference": "CVE-2022-2621",
                "Description": "Chain: two threads in a web browser use the same resource (CWE-366), but one of those threads can destroy the resource before the other has completed (CWE-416).",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2022-2621"
            },
            {
                "Reference": "CVE-2021-0920",
                "Description": "Chain: mobile platform race condition (CWE-362) leadingto use-after-free (CWE-416), as exploited in the wild per CISA KEV.",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2021-0920"
            },
            {
                "Reference": "CVE-2020-6819",
                "Description": "Chain: race condition (CWE-362) leads to use-after-free (CWE-416), as exploited in the wild per CISA KEV.",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2020-6819"
            },
            {
                "Reference": "CVE-2010-4168",
                "Description": "Use-after-free triggered by closing a connection while data is still being transmitted.",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2010-4168"
            },
            {
                "Reference": "CVE-2010-2941",
                "Description": "Improper allocation for invalid data leads to use-after-free.",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2010-2941"
            },
            {
                "Reference": "CVE-2010-2547",
                "Description": "certificate with a large number of Subject Alternate Names not properly handled in realloc, leading to use-after-free",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2010-2547"
            },
            {
                "Reference": "CVE-2010-1772",
                "Description": "Timers are not disabled when a related object is deleted",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2010-1772"
            },
            {
                "Reference": "CVE-2010-1437",
                "Description": "Access to a \"dead\" object that is being cleaned up",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2010-1437"
            },
            {
                "Reference": "CVE-2010-1208",
                "Description": "object is deleted even with a non-zero reference count, and later accessed",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2010-1208"
            },
            {
                "Reference": "CVE-2010-0629",
                "Description": "use-after-free involving request containing an invalid version number",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2010-0629"
            },
            {
                "Reference": "CVE-2010-0378",
                "Description": "unload of an object that is currently being accessed by other functionality",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2010-0378"
            },
            {
                "Reference": "CVE-2010-0302",
                "Description": "incorrectly tracking a reference count leads to use-after-free",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2010-0302"
            },
            {
                "Reference": "CVE-2010-0249",
                "Description": "use-after-free related to use of uninitialized memory",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2010-0249"
            },
            {
                "Reference": "CVE-2010-0050",
                "Description": "HTML document with incorrectly-nested tags",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2010-0050"
            },
            {
                "Reference": "CVE-2009-3658",
                "Description": "Use after free in ActiveX object by providing a malformed argument to a method",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2009-3658"
            },
            {
                "Reference": "CVE-2009-3616",
                "Description": "use-after-free by disconnecting during data transfer, or a message containing incorrect data types",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2009-3616"
            },
            {
                "Reference": "CVE-2009-3553",
                "Description": "disconnect during a large data transfer causes incorrect reference count, leading to use-after-free",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2009-3553"
            },
            {
                "Reference": "CVE-2009-2416",
                "Description": "use-after-free found by fuzzing",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2009-2416"
            },
            {
                "Reference": "CVE-2009-1837",
                "Description": "Chain: race condition (CWE-362) from improper handling of a page transition in web client while an applet is loading (CWE-368) leads to use after free (CWE-416)",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2009-1837"
            },
            {
                "Reference": "CVE-2009-0749",
                "Description": "realloc generates new buffer and pointer, but previous pointer is still retained, leading to use after free",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2009-0749"
            },
            {
                "Reference": "CVE-2010-3328",
                "Description": "Use-after-free in web browser, probably resultant from not initializing memory.",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2010-3328"
            },
            {
                "Reference": "CVE-2008-5038",
                "Description": "use-after-free when one thread accessed memory that was freed by another thread",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2008-5038"
            },
            {
                "Reference": "CVE-2008-0077",
                "Description": "assignment of malformed values to certain properties triggers use after free",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2008-0077"
            },
            {
                "Reference": "CVE-2006-4434",
                "Description": "mail server does not properly handle a long header.",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2006-4434"
            },
            {
                "Reference": "CVE-2010-2753",
                "Description": "Chain: integer overflow leads to use-after-free",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2010-2753"
            },
            {
                "Reference": "CVE-2006-4997",
                "Description": "freed pointer dereference",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2006-4997"
            },
            {
                "Reference": "CVE-2003-0813",
                "Description": "Chain: A multi-threaded race condition (CWE-367) allows attackers to cause two threads to process the same RPC request, which causes a use-after-free (CWE-416) in one thread",
                "Link": "https://www.cve.org/CVERecord?id=CVE-2003-0813"
            }
        ]
    },
    "Functional_Areas": {
        "Functional_Area": "Memory Management"
    },
    "Affected_Resources": {
        "Affected_Resource": "Memory"
    },
    "Taxonomy_Mappings": {
        "Taxonomy_Mapping": [
            {
                "@Taxonomy_Name": "ISA/IEC 62443",
                "Entry_ID": "Part 4-1",
                "Entry_Name": "Req SI-1"
            },
            {
                "@Taxonomy_Name": "7 Pernicious Kingdoms",
                "Entry_Name": "Use After Free"
            },
            {
                "@Taxonomy_Name": "CLASP",
                "Entry_Name": "Using freed memory"
            },
            {
                "@Taxonomy_Name": "CERT C Secure Coding",
                "Entry_ID": "MEM00-C",
                "Entry_Name": "Allocate and free memory in the same module, at the same level of abstraction"
            },
            {
                "@Taxonomy_Name": "CERT C Secure Coding",
                "Entry_ID": "MEM01-C",
                "Entry_Name": "Store a new value in pointers immediately after free()"
            },
            {
                "@Taxonomy_Name": "CERT C Secure Coding",
                "Entry_ID": "MEM30-C",
                "Entry_Name": "Do not access freed memory",
                "Mapping_Fit": "Exact"
            },
            {
                "@Taxonomy_Name": "Software Fault Patterns",
                "Entry_ID": "SFP15",
                "Entry_Name": "Faulty Resource Use"
            }
        ]
    },
    "References": {
        "Reference": [
            {
                "@External_Reference_ID": "REF-6"
            },
            {
                "@External_Reference_ID": "REF-18"
            },
            {
                "@External_Reference_ID": "REF-44",
                "@Section": "\"Sin 8: C++ Catastrophes.\" Page 143"
            },
            {
                "@External_Reference_ID": "REF-1518"
            },
            {
                "@External_Reference_ID": "REF-1534"
            }
        ]
    },
    "Mapping_Notes": {
        "Usage": "Allowed",
        "Rationale": "This CWE entry is at the Variant level of abstraction, which is a preferred level of abstraction for mapping to the root causes ofvulnerabilities.",
        "Comments": "Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.",
        "Reasons": {
            "Reason": {
                "@Type": "Acceptable-Use"
            }
        }
    },
    "Content_History": {
        "Submission": {
            "Submission_Name": "7 Pernicious Kingdoms",
            "Submission_Date": "2006-07-19",
            "Submission_Version": "Draft 3",
            "Submission_ReleaseDate": "2006-07-19"
        },
        "Modification": [
            {
                "Modification_Name": "Eric Dalci",
                "Modification_Organization": "Cigital",
                "Modification_Date": "2008-07-01",
                "Modification_Version": "1.0",
                "Modification_ReleaseDate": "2008-09-09",
                "Modification_Comment": "updated Potential_Mitigations, Time_of_Introduction"
            },
            {
                "Modification_Organization": "KDM Analytics",
                "Modification_Date": "2008-08-01",
                "Modification_Version": "1.0",
                "Modification_ReleaseDate": "2008-09-09",
                "Modification_Comment": "added/updated white box definitions"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2008-09-08",
                "Modification_Version": "1.0",
                "Modification_ReleaseDate": "2008-09-09",
                "Modification_Comment": "updated Applicable_Platforms, Common_Consequences, Relationships, Observed_Example, Other_Notes, Taxonomy_Mappings"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2008-11-24",
                "Modification_Version": "1.1",
                "Modification_ReleaseDate": "2008-11-25",
                "Modification_Comment": "updated Relationships, Taxonomy_Mappings"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2009-03-10",
                "Modification_Version": "1.3",
                "Modification_ReleaseDate": "2009-03-10",
                "Modification_Comment": "updated Demonstrative_Examples"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2009-05-27",
                "Modification_Version": "1.4",
                "Modification_ReleaseDate": "2009-05-27",
                "Modification_Comment": "updated Demonstrative_Examples"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2009-10-29",
                "Modification_Version": "1.6",
                "Modification_ReleaseDate": "2009-10-29",
                "Modification_Comment": "updated Common_Consequences"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2010-02-16",
                "Modification_Version": "1.8",
                "Modification_ReleaseDate": "2010-02-16",
                "Modification_Comment": "updated Relationships"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2010-06-21",
                "Modification_Version": "1.9",
                "Modification_ReleaseDate": "2010-06-21",
                "Modification_Comment": "updated Potential_Mitigations"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2010-09-27",
                "Modification_Version": "1.10",
                "Modification_ReleaseDate": "2010-09-27",
                "Modification_Comment": "updated Observed_Examples, Relationships"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2010-12-13",
                "Modification_Version": "1.11",
                "Modification_ReleaseDate": "2010-12-13",
                "Modification_Comment": "updated Alternate_Terms, Common_Consequences, Description, Observed_Examples, Other_Notes, Potential_Mitigations, Relationships"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2011-03-29",
                "Modification_Version": "1.12",
                "Modification_ReleaseDate": "2011-03-30",
                "Modification_Comment": "updated Description"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2011-06-01",
                "Modification_Version": "1.13",
                "Modification_ReleaseDate": "2011-06-01",
                "Modification_Comment": "updated Common_Consequences"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2011-06-27",
                "Modification_Version": "2.0",
                "Modification_ReleaseDate": "2011-06-27",
                "Modification_Comment": "updated Demonstrative_Examples"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2011-09-13",
                "Modification_Version": "2.1",
                "Modification_ReleaseDate": "2011-09-13",
                "Modification_Comment": "updated Relationships, Taxonomy_Mappings"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2012-05-11",
                "Modification_Version": "2.2",
                "Modification_ReleaseDate": "2012-05-15",
                "Modification_Comment": "updated References, Relationships"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2014-07-30",
                "Modification_Version": "2.8",
                "Modification_ReleaseDate": "2014-07-31",
                "Modification_Comment": "updated Relationships, Taxonomy_Mappings"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2015-12-07",
                "Modification_Version": "2.9",
                "Modification_ReleaseDate": "2015-12-07",
                "Modification_Comment": "updated Relationships"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2017-11-08",
                "Modification_Version": "3.0",
                "Modification_ReleaseDate": "2017-11-08",
                "Modification_Comment": "updated Demonstrative_Examples, Relationships, Taxonomy_Mappings, White_Box_Definitions"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2019-01-03",
                "Modification_Version": "3.2",
                "Modification_ReleaseDate": "2019-01-03",
                "Modification_Comment": "updated Relationships"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2019-06-20",
                "Modification_Version": "3.3",
                "Modification_ReleaseDate": "2019-06-20",
                "Modification_Comment": "updated Relationships, Type"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2019-09-19",
                "Modification_Version": "3.4",
                "Modification_ReleaseDate": "2019-09-19",
                "Modification_Comment": "updated Relationships"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2020-02-24",
                "Modification_Version": "4.0",
                "Modification_ReleaseDate": "2020-02-24",
                "Modification_Comment": "updated References, Relationships, Taxonomy_Mappings"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2020-06-25",
                "Modification_Version": "4.1",
                "Modification_ReleaseDate": "2020-06-25",
                "Modification_Comment": "updated Relationships"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2020-08-20",
                "Modification_Version": "4.2",
                "Modification_ReleaseDate": "2020-08-20",
                "Modification_Comment": "updated Relationships"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2020-12-10",
                "Modification_Version": "4.3",
                "Modification_ReleaseDate": "2020-12-10",
                "Modification_Comment": "updated Relationships"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2021-07-20",
                "Modification_Version": "4.5",
                "Modification_ReleaseDate": "2021-07-20",
                "Modification_Comment": "updated Relationships"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2022-06-28",
                "Modification_Version": "4.8",
                "Modification_ReleaseDate": "2022-06-28",
                "Modification_Comment": "updated Observed_Examples, Relationships"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2022-10-13",
                "Modification_Version": "4.9",
                "Modification_ReleaseDate": "2022-10-13",
                "Modification_Comment": "updated Description, Relationships, Taxonomy_Mappings"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2023-04-27",
                "Modification_Version": "4.11",
                "Modification_ReleaseDate": "2023-04-27",
                "Modification_Comment": "updated Detection_Factors, Relationships, Time_of_Introduction"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2023-06-29",
                "Modification_Version": "4.12",
                "Modification_ReleaseDate": "2023-06-29",
                "Modification_Comment": "updated Mapping_Notes, Relationships"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2023-10-26",
                "Modification_Version": "4.13",
                "Modification_ReleaseDate": "2023-10-26",
                "Modification_Comment": "updated Observed_Examples"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2024-02-29",
                "Modification_Version": "4.14",
                "Modification_ReleaseDate": "2024-02-29",
                "Modification_Comment": "updated Taxonomy_Mappings"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2024-07-16",
                "Modification_Version": "4.15",
                "Modification_ReleaseDate": "2024-07-16",
                "Modification_Comment": "updated Alternate_Terms, Common_Consequences, Description, Diagram, Potential_Mitigations, Relationships, Weakness_Ordinalities"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2024-11-19",
                "Modification_Version": "4.16",
                "Modification_ReleaseDate": "2024-11-19",
                "Modification_Comment": "updated Relationships"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2025-04-03",
                "Modification_Version": "4.17",
                "Modification_ReleaseDate": "2025-04-03",
                "Modification_Comment": "updated Observed_Examples"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2025-09-09",
                "Modification_Version": "4.18",
                "Modification_ReleaseDate": "2025-09-09",
                "Modification_Comment": "updated Functional_Areas"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2025-12-11",
                "Modification_Version": "4.19",
                "Modification_ReleaseDate": "2025-12-11",
                "Modification_Comment": "updated Applicable_Platforms, Detection_Factors, References, Relationships"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2026-04-30",
                "Modification_Version": "4.20",
                "Modification_ReleaseDate": "2026-04-30",
                "Modification_Comment": "updated Common_Consequences, Observed_Examples"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2026-10-28",
                "Modification_Version": "5.0",
                "Modification_ReleaseDate": "2026-10-28",
                "Modification_Comment": "updated Observed_Examples, References"
            }
        ],
        "Contribution": [
            {
                "@Type": "Feedback",
                "Contribution_Name": "Anonymous External Contributor",
                "Contribution_Date": "2022-06-28",
                "Contribution_Version": "4.9",
                "Contribution_ReleaseDate": "2022-10-13",
                "Contribution_Comment": "Suggested rephrase for extended description"
            },
            {
                "@Type": "Content",
                "Contribution_Name": "participants in the CWE ICS/OT SIG 62443 Mapping Fall Workshop",
                "Contribution_Date": "2023-11-14",
                "Contribution_Version": "4.14",
                "Contribution_ReleaseDate": "2024-02-29",
                "Contribution_Comment": "Contributed or reviewed taxonomy mappings for ISA/IEC 62443"
            },
            {
                "@Type": "Content",
                "Contribution_Name": "Abhi Balakrishnan",
                "Contribution_Date": "2024-02-29",
                "Contribution_Version": "4.15",
                "Contribution_ReleaseDate": "2024-07-16",
                "Contribution_Comment": "Provided diagram to improve CWE usability"
            }
        ]
    }
}
```

#### Groupings

Example grouping:

```json
{
    "@ID": "1162",
    "@Name": "SEI CERT C Coding Standard - Guidelines 08. Memory Management (MEM)",
    "@Status": "Stable",
    "Summary": "Weaknesses in thiscategory are related to the rules and recommendations in the Memory Management (MEM) section of the SEI CERT C Coding Standard.",
    "Relationships": {
        "Has_Member": [
            {
                "@CWE_ID": "416",
                "@View_ID": "1154"
            },
            {
                "@CWE_ID": "672",
                "@View_ID": "1154"
            },
            {
                "@CWE_ID": "758",
                "@View_ID": "1154"
            },
            {
                "@CWE_ID": "666",
                "@View_ID": "1154"
            },
            {
                "@CWE_ID": "415",
                "@View_ID": "1154"
            },
            {
                "@CWE_ID": "401",
                "@View_ID": "1154"
            },
            {
                "@CWE_ID": "404",
                "@View_ID": "1154"
            },
            {
                "@CWE_ID": "459",
                "@View_ID": "1154"
            },
            {
                "@CWE_ID": "771",
                "@View_ID": "1154"
            },
            {
                "@CWE_ID": "772",
                "@View_ID": "1154"
            },
            {
                "@CWE_ID": "590",
                "@View_ID": "1154"
            },
            {
                "@CWE_ID": "131",
                "@View_ID": "1154"
            },
            {
                "@CWE_ID": "680",
                "@View_ID": "1154"
            },
            {
                "@CWE_ID": "467",
                "@View_ID": "1154"
            },
            {
                "@CWE_ID": "789",
                "@View_ID": "1154"
            },
            {
                "@CWE_ID": "190",
                "@View_ID": "1154"
            }
        ]
    },
    "References": {
        "Reference": [
            {
                "@External_Reference_ID": "REF-606"
            },
            {
                "@External_Reference_ID": "REF-986"
            }
        ]
    },
    "Mapping_Notes": {
        "Usage": "Prohibited",
        "Rationale": "This entry is a Grouping. Using groupings for mapping has been discouraged since 2019. They are informal organizational groupings of weaknesses that can help CWE users with data aggregation, navigation, and browsing. However, they are not weaknesses in themselves.",
        "Comments": "See member weaknesses of this category.",
        "Reasons": {
            "Reason": {
                "@Type": "Grouping"
            }
        }
    },
    "Content_History": {
        "Submission": {
            "Submission_Name": "CWE Content Team",
            "Submission_Organization": "MITRE",
            "Submission_Date": "2018-12-18",
            "Submission_Version": "3.2",
            "Submission_ReleaseDate": "2019-01-03"
        },
        "Modification": [
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2023-04-27",
                "Modification_Version": "4.11",
                "Modification_ReleaseDate": "2023-04-27",
                "Modification_Comment": "updated Mapping_Notes"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2023-06-29",
                "Modification_Version": "4.12",
                "Modification_ReleaseDate": "2023-06-29",
                "Modification_Comment": "updated Mapping_Notes"
            },
            {
                "Modification_Name": "CWE Content Team",
                "Modification_Organization": "MITRE",
                "Modification_Date": "2026-10-28",
                "Modification_Version": "5.0",
                "Modification_ReleaseDate": "2026-10-28",
                "Modification_Comment": "updated Mapping_Notes, Type"
            }
        ]
    }
}
```

#### Views

Example view:

```xml
<View ID="868" Name="Weaknesses Addressed by the SEI CERT C++ Coding Standard (2016 Version)" Type="Graph" Status="Obsolete">
   <Objective>CWE entries in this view (graph) are fully or partially eliminated by following the SEI CERT C++ Coding Standard, as published in 2016. This view is no longer being actively maintained, since it statically represents the coding rules as they were in 2016.</Objective>
   <Audience>
      <Stakeholder>
         <Type>Software Developers</Type>
         <Description>By following the CERT C++ Secure Coding Standard, developers will be able to fully or partially prevent the weaknesses that are identified in this view. In addition, developers can use a CWE coverage graph to determine which weaknesses are not directly addressed by the standard, which will help identify and resolve remaining gaps in training, tool acquisition, or other approaches for reducing weaknesses.</Description>
      </Stakeholder>
      <Stakeholder>
         <Type>Product Customers</Type>
         <Description>If a software developer claims to be following the CERT C++ Secure Coding Standard, then customers can search for the weaknesses in this view in order to formulate independent evidence of that claim.</Description>
      </Stakeholder>
      <Stakeholder>
         <Type>Educators</Type>
         <Description>Educators can use this view in multiple ways. For example, if there is a focus on teaching weaknesses, the educator could link them to the relevant Secure Coding Standard.</Description>
      </Stakeholder>
   </Audience>
   <Members>
      <Has_Member CWE_ID="869" View_ID="868"/>
      <Has_Member CWE_ID="870" View_ID="868"/>
      <Has_Member CWE_ID="871" View_ID="868"/>
      <Has_Member CWE_ID="872" View_ID="868"/>
      <Has_Member CWE_ID="873" View_ID="868"/>
      <Has_Member CWE_ID="874" View_ID="868"/>
      <Has_Member CWE_ID="875" View_ID="868"/>
      <Has_Member CWE_ID="876" View_ID="868"/>
      <Has_Member CWE_ID="877" View_ID="868"/>
      <Has_Member CWE_ID="878" View_ID="868"/>
      <Has_Member CWE_ID="879" View_ID="868"/>
      <Has_Member CWE_ID="880" View_ID="868"/>
      <Has_Member CWE_ID="881" View_ID="868"/>
      <Has_Member CWE_ID="882" View_ID="868"/>
      <Has_Member CWE_ID="883" View_ID="868"/>
   </Members>
   <References>
      <Reference External_Reference_ID="REF-847"/>
   </References>
   <Mapping_Notes>
      <Usage>Prohibited</Usage>
      <Rationale>This entry is a View. Views are not weaknesses and therefore inappropriate to describe the root causes of vulnerabilities.</Rationale>
      <Comments>Use this View or other Views to search and navigate for the appropriate weakness.</Comments>
      <Reasons>
         <Reason Type="View"/>
      </Reasons>
   </Mapping_Notes>
   <Notes>
      <Note Type="Relationship">The relationships in this view were determined based on specific statements within the rules from the standard. Not all rules have direct relationships to individual weaknesses, although they likely have chaining relationships in specific circumstances.</Note>
   </Notes>
   <Content_History>
      <Submission>
         <Submission_Name>CWE Content Team</Submission_Name>
         <Submission_Organization>MITRE</Submission_Organization>
         <Submission_Date>2011-08-04</Submission_Date>
         <Submission_Version>2.1</Submission_Version>
         <Submission_ReleaseDate>2011-09-13</Submission_ReleaseDate>
      </Submission>
      <Modification>
         <Modification_Name>CWE Content Team</Modification_Name>
         <Modification_Organization>MITRE</Modification_Organization>
         <Modification_Date>2019-01-03</Modification_Date>
         <Modification_Version>3.2</Modification_Version>
         <Modification_ReleaseDate>2019-01-03</Modification_ReleaseDate>
         <Modification_Comment>updated Description, Maintenance_Notes, Name, References</Modification_Comment>
      </Modification>
      <Modification>
         <Modification_Name>CWE Content Team</Modification_Name>
         <Modification_Organization>MITRE</Modification_Organization>
         <Modification_Date>2020-02-24</Modification_Date>
         <Modification_Version>4.0</Modification_Version>
         <Modification_ReleaseDate>2020-02-24</Modification_ReleaseDate>
         <Modification_Comment>updated View_Audience</Modification_Comment>
      </Modification>
      <Modification>
         <Modification_Name>CWE Content Team</Modification_Name>
         <Modification_Organization>MITRE</Modification_Organization>
         <Modification_Date>2021-03-15</Modification_Date>
         <Modification_Version>4.4</Modification_Version>
         <Modification_ReleaseDate>2021-03-15</Modification_ReleaseDate>
         <Modification_Comment>updated Description, Maintenance_Notes</Modification_Comment>
      </Modification>
      <Modification>
         <Modification_Name>CWE Content Team</Modification_Name>
         <Modification_Organization>MITRE</Modification_Organization>
         <Modification_Date>2023-06-29</Modification_Date>
         <Modification_Version>4.12</Modification_Version>
         <Modification_ReleaseDate>2023-06-29</Modification_ReleaseDate>
         <Modification_Comment>updated Mapping_Notes</Modification_Comment>
      </Modification>
   <Previous_Entry_Name Date="2019-01-03">Weaknesses Addressed by the CERT C++ Secure Coding Standard</Previous_Entry_Name>
   </Content_History>
</View>
```