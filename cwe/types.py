import datetime
import dataclasses
import itertools
import re
from typing import Iterable, Iterator, List, Optional, Tuple
from dataclasses import dataclass


HIGH = 'High'
MEDIUM = 'Medium'
LOW = 'Low'

INCOMPLETE = 'Incomplete'
DRAFT = 'Draft'
STABLE = 'Stable'
DEPRECATED = 'Deprecated'
OBSOLETE = 'Obsolete'


@dataclass()
class WeaknessCatalog:
    name: str
    version: str
    date: datetime.date
    weaknesses: List[Weakness]
    groupings: List[Grouping]
    views: List[View]
    external_references: List[ExternalReference]

    def iter_weaknesses(
            self,
            weakness_ids: Optional[Iterable[str]] = None,
            confidentiality_impact: Optional[bool] = None, 
            integrity_impact: Optional[bool] = None, 
            availability_impact: Optional[bool] = None) -> Iterator[Weakness]:

        for w in self.weaknesses:
            if weakness_ids is not None and f'CWE-{w.id}' not in weakness_ids:
                continue

            if confidentiality_impact is not None and confidentiality_impact != w.confidentiality_impact:
                continue
            
            if integrity_impact is not None and integrity_impact != w.integrity_impact:
                continue
            
            if availability_impact is not None and availability_impact != w.availability_impact:
                continue

            yield w

    def iter_groupings(self) -> Iterator[Grouping]:
        for g in self.groupings:
            yield g

    def iter_views(self) -> Iterator[View]:
        for v in self.views:
            yield v

    def iter_external_references(self) -> Iterator[ExternalReference]:
        for ref in self.external_references:
            yield ref

    def get_map_of_weaknesses_to_capec_techniques(self) -> dict:
        m = {}
        for w in self.weaknesses:
            weakness_id = f'CWE-{w.id}'
            technique_ids = [f'CAPEC-{t}' for t in w.related_attack_patterns]
            m[weakness_id] = technique_ids
        return m

    def get_map_of_weaknesses_to_cve_vulnerabilities(self) -> dict:
        m = {}
        for w in self.weaknesses:
            weakness_id = f'CWE-{w.id}'
            cve_ids = [f'CVE-{cve}' for cve in w.related_cve_ids]
            m[weakness_id] = cve_ids
        return m


@dataclass()
class ExternalReference:
    id: str
    name: str
    authors: List[str]
    publication_date: Optional[str]  # ISO 8601, at the precision published: YYYY, YYYY-MM, or YYYY-MM-DD
    edition: Optional[str]
    publication: Optional[str]
    publisher: Optional[str]
    url: Optional[str]
    url_date: Optional[str]
    alt_url: Optional[str]
    alt_url_date: Optional[str]
    access_restrictions: Optional[str]
    media_types: List[str]
    rationales: List[str]


@dataclass()
class ExternalReferenceCitation:
    external_reference_id: str      # e.g. REF-44
    section: Optional[str]          # e.g. Sin 8: C++ Catastrophes


@dataclass()
class CustomPhase:
    name: str                       # e.g. Training
    domain: Optional[str]           # e.g. AI


@dataclass()
class Consequence:
    scope: List[str]
    impact: List[str]
    note: Optional[str]
    likelihood: Optional[str]

    @property
    def cia(self) -> Tuple[bool, bool, bool]:
        return (
            self.confidentiality_impact,
            self.integrity_impact,
            self.availability_impact
        )

    @property
    def confidentiality_impact(self) -> bool:
        return self.has_confidentiality_impact()

    @property
    def integrity_impact(self) -> bool:
        return self.has_integrity_impact()

    @property
    def availability_impact(self) -> bool:
        return self.has_availability_impact()

    def has_confidentiality_impact(self) -> bool:
        return 'Confidentiality' in self.scope

    def has_integrity_impact(self) -> bool:
        return 'Integrity' in self.scope

    def has_availability_impact(self) -> bool:
        return 'Availability' in self.scope

    def has_high_likelihood(self) -> bool:
        return self.likelihood == 'High'

    def has_medium_likelihood(self) -> bool:
        return self.likelihood == 'Medium'

    def has_low_likelihood(self) -> bool:
        return self.likelihood == 'Low'


@dataclass()
class ModeOfIntroduction:
    phase: List[str]
    custom_phases: List[CustomPhase]
    note: Optional[str]


@dataclass()
class DetectionMethod:
    id: Optional[str]
    name: str
    phase: List[str]
    custom_phases: List[CustomPhase]
    description: Optional[str]
    effectiveness: Optional[str]
    effectiveness_notes: Optional[str]


@dataclass()
class Weakness:
    id: str
    name: str
    abstraction: str
    structure: str
    status: str
    description: str
    extended_description: Optional[str]
    diagram: Optional[str]
    affected_resources: List[str]
    alternate_terms: List[AlternateTerm]
    applicable_platforms: List[PlatformReference]
    background_details: List[str]
    common_consequences: List[Consequence]
    contribution_history: List[Contribution]
    demonstrative_examples: List[DemonstrativeExample]
    detection_methods: List[DetectionMethod]
    dimensions: List[Dimension]
    functional_areas: List[str]
    likelihood_of_exploitation: Optional[str]
    mapping_notes: Optional[MappingNotes]
    modes_of_introduction: List[ModeOfIntroduction]
    modification_history: List[Modification]
    notes: List[Note]
    observed_examples: List[ObservedExample]
    potential_mitigations: List[Mitigation]
    previous_entry_names: List[PreviousEntryName]
    references: List[ExternalReferenceCitation]
    related_attack_patterns: List[str]
    related_weaknesses: List[WeaknessReference]
    submission_history: List[Submission]
    taxonomy_mappings: List[TaxonomyMapping]
    technical_nuance: Optional[str]
    weakness_ordinalities: List[WeaknessOrdinality]

    @property
    def cwe_id(self) -> str:
        return f'CWE-{self.id}'

    @property
    def impact_scope(self) -> List[str]:
        return sorted(set(itertools.chain.from_iterable(c.scope for c in self.common_consequences)))

    @property
    def confidentiality_impact(self) -> bool:
        return self.has_confidentiality_impact()

    @property
    def integrity_impact(self) -> bool:
        return self.has_integrity_impact()

    @property
    def availability_impact(self) -> bool:
        return self.has_availability_impact()

    def has_confidentiality_impact(self) -> bool:
        return any(c.confidentiality_impact for c in self.common_consequences)

    def has_integrity_impact(self) -> bool:
        return any(c.integrity_impact for c in self.common_consequences)

    def has_availability_impact(self) -> bool:
        return any(c.availability_impact for c in self.common_consequences)

    @property
    def can_precede(self) -> List[str]:
        return [r.cwe_id for r in self.related_weaknesses if r.is_can_precede_reference()]

    @property
    def child_of(self) -> List[str]:
        return [r.cwe_id for r in self.related_weaknesses if r.is_child_of_reference()]

    @property
    def external_reference_ids(self) -> List[str]:
        return [r.external_reference_id for r in self.references]

    @property
    def related_cwe_ids(self) -> List[str]:
        return sorted({r.cwe_id for r in self.related_weaknesses})

    @property
    def related_cve_ids(self) -> List[str]:
        return sorted({o.reference for o in self.observed_examples if o.is_cve_id()})


@dataclass()
class WeaknessOrdinality:
    ordinality: str                 # e.g. Primary, Resultant, Indirect
    description: Optional[str]


@dataclass()
class Dimension:
    type: str                       # e.g. Behavior-Type
    value: str                      # e.g. Comparison


@dataclass()
class WeaknessReference:
    weakness_id: str
    view_id: Optional[str]
    nature: Optional[str]           # e.g. ChildOf, CanPrecede, or HasMember (members of groupings and views)
    ordinal: Optional[str]
    chain_id: Optional[str]
    dimensions: List[Dimension]

    def is_child_of_reference(self) -> bool:
        return self.nature in ('ChildOf', 'child-of')

    def is_can_precede_reference(self) -> bool:
        return self.nature in ('CanPrecede', 'can-precede')

    def is_has_member_reference(self) -> bool:
        return self.nature in ('HasMember', 'has-member')


@dataclass()
class PlatformReference:
    type: str                       # Language, Operating System, Architecture, or Technology
    name: Optional[str]             # e.g. C, C++
    platform_class: Optional[str]   # e.g. Memory-Unsafe
    prevalence: Optional[str]       # e.g. Often
    note: Optional[str]

    def is_language(self) -> bool:
        return self.type == 'Language'


@dataclass()
class TaxonomyMapping:
    taxonomy_name: str
    entry_id: Optional[str]
    entry_name: Optional[str]
    mapping_fit: Optional[str]


@dataclass()
class MappingSuggestion:
    cwe_id: str
    comment: Optional[str]


@dataclass()
class MappingNotes:
    usage: str
    rationale: Optional[str]
    comments: Optional[str]
    reasons: List[str]
    suggestions: List[MappingSuggestion]


@dataclass()
class Modification:
    name: Optional[str]
    organization: Optional[str]
    date: Optional[str]
    version: Optional[str]
    release_date: Optional[str]
    comment: Optional[str]
    importance: Optional[str]


@dataclass()
class Contribution:
    type: Optional[str]             # e.g. Content, Feedback
    names: List[str]
    organization: Optional[str]
    date: Optional[str]
    version: Optional[str]
    release_date: Optional[str]
    comment: Optional[str]


@dataclass()
class Submission:
    names: List[str]
    organization: Optional[str]
    date: Optional[str]
    version: Optional[str]
    release_date: Optional[str]
    comment: Optional[str]


@dataclass()
class PreviousEntryName:
    name: str
    date: Optional[str]
    version: Optional[str]


@dataclass()
class AlternateTerm:
    name: str
    description: Optional[str]
    roles: List[str]                # e.g. Common-Name, Acronym


@dataclass()
class Mitigation:
    id: Optional[str]
    phase: List[str]
    custom_phases: List[CustomPhase]
    strategy: Optional[str]
    description: Optional[str]
    effectiveness: Optional[str]
    effectiveness_notes: Optional[str]


@dataclass()
class DemonstrativeExampleBlock:
    type: str                       # text (from `Body_Text`) or code (from `Example_Code`)
    content: str
    nature: Optional[str]           # code only, e.g. Bad, Good, Attack, Result, Informative
    language: Optional[str]         # code only, e.g. Java

    def is_code(self) -> bool:
        return self.type == 'code'


@dataclass()
class DemonstrativeExample:
    id: Optional[str]
    intro_text: Optional[str]
    body: List[DemonstrativeExampleBlock]   # text and code blocks, in document order
    references: List[ExternalReferenceCitation]


@dataclass()
class ObservedExample:
    reference: str
    description: Optional[str]
    link: Optional[str]
    rationales: List[str]

    def is_cve_id(self) -> bool:
        return re.match(r'^CVE-\d{4}-\d{4,}$', self.reference) is not None


@dataclass()
class Note:
    note_type: Optional[str]
    value: str
    version: Optional[str]
    release_date: Optional[str]


@dataclass()
class Grouping:
    id: str
    name: str
    description: str
    status: str
    members: List[WeaknessReference]    # weaknesses and groupings, with nature = HasMember
    taxonomy_mappings: List[TaxonomyMapping]
    references: List[ExternalReferenceCitation]
    mapping_notes: Optional[MappingNotes]
    notes: List[Note]
    submission_history: List[Submission]
    modification_history: List[Modification]
    contribution_history: List[Contribution]
    previous_entry_names: List[PreviousEntryName]

    @property
    def external_reference_ids(self) -> List[str]:
        return [r.external_reference_id for r in self.references]

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
class View:
    id: str
    name: str
    type: str
    status: str
    objective: Optional[str]
    audience: List[Stakeholder]
    members: List[WeaknessReference]    # weaknesses and groupings, with nature = HasMember
    filter: Optional[str]               # XPath query that selects the members of an implicit view
    references: List[ExternalReferenceCitation]
    mapping_notes: Optional[MappingNotes]
    notes: List[Note]
    submission_history: List[Submission]
    modification_history: List[Modification]
    contribution_history: List[Contribution]
    previous_entry_names: List[PreviousEntryName]

    @property
    def external_reference_ids(self) -> List[str]:
        return [r.external_reference_id for r in self.references]

    def is_obsolete(self) -> bool:
        return self.status == OBSOLETE
