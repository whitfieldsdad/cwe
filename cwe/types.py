from dataclasses import dataclass
import datetime
from typing import Iterator, List, Optional

ACCESS_CONTROL = 'Access Control'
ACCOUNTABILITY = 'Accountability'
AUTHENTICATION = 'Authentication'
AUTHORIZATION = 'Authorization'
AVAILABILITY = 'Availability'
CONFIDENTIALITY = 'Confidentiality'
INTEGRITY = 'Integrity'
NON_REPUDIATION = 'Non-Repudiation'
OTHER = 'Other'


@dataclass()
class RelatedWeakness:
    id: str
    nature: str
    view_id: str
    ordinal: Optional[str]

    @property
    def cwe_id(self) -> str:
        return self.id


@dataclass()
class Submission:
    name: Optional[str]
    organization: Optional[str]
    date: datetime.date
    release_date: datetime.date
    version: str


@dataclass()
class Modification:
    name: Optional[str]
    organization: Optional[str]
    date: datetime.date
    comment: Optional[str]


@dataclass()
class ContentHistory:
    submission: Submission
    modifications: List[Modification]


@dataclass()
class Consequence:
    scope: List[str]
    impact: List[str]
    note: Optional[str]

    @property
    def tags(self) -> List[str]:
        return sorted(set(self.scope) | set(self.impact))

    def related_to_confidentiality(self) -> bool:
        return CONFIDENTIALITY in self.tags
    
    def related_to_integrity(self) -> bool:
        return INTEGRITY in self.tags

    def related_to_availability(self) -> bool:
        return AVAILABILITY in self.tags
    
    def related_to_access_control(self) -> bool:
        return ACCESS_CONTROL in self.tags
    
    def related_to_non_repudiation(self) -> bool:
        return NON_REPUDIATION in self.tags
    
    def related_to_authentication(self) -> bool:
        return AUTHENTICATION in self.tags
    
    def related_to_authorization(self) -> bool:
        return AUTHORIZATION in self.tags
    
    def related_to_denial_of_service(self) -> bool:
        for i in self.impact:
            if i.startswith('DoS'):
                return True
        return False
    
    def related_to_memory(self) -> bool:
        for i in self.impact:
            if 'Memory' in i:
                return True
        return False
    

@dataclass()
class DetectionMethod:
    id: Optional[str]
    method: str


@dataclass()
class DetectionNotes(DetectionMethod):
    effectiveness: Optional[str]
    description: Optional[str]

    @property
    def name(self) -> str:
        return self.method


@dataclass()
class Mitigation:
    id: Optional[str]
    phases: List[str]
    strategy: Optional[str]
    description: Optional[str]
    effectiveness: Optional[str]
    effectiveness_notes: Optional[str]


@dataclass()
class ModeOfIntroduction:
    phase: str
    note: Optional[str]


@dataclass()
class ObservedExample:
    reference: str
    description: str
    link: str

    def is_cve_reference(self) -> bool:
        return self.reference and self.reference.startswith('CVE-')


@dataclass()
class MappingNotes:
    usage: str
    rationale: str
    comments: Optional[str]
    reasons: List[str]


@dataclass()
class Weakness:
    id: str
    name: str
    alternate_terms: List[str]
    abstraction: str
    structure: str
    status: str
    description: str
    extended_description: Optional[str]
    background_details: Optional[str]
    common_consequences: List[Consequence]
    detection_notes: List[DetectionNotes]
    content_history: ContentHistory
    likelihood_of_exploit: Optional[str]
    mapping_notes: MappingNotes
    mitigations: List[Mitigation]
    modes_of_introduction: List[ModeOfIntroduction]
    observed_examples: List[ObservedExample]
    related_weaknesses: List[RelatedWeakness]
    related_attack_patterns: List[str]

    @property
    def detection_methods(self) -> List[DetectionMethod]:
        methods = []
        for note in self.detection_notes:
            if note.id:
                method = DetectionMethod(id=note.id, method=note.method)
                if method not in methods:
                    methods.append(method)
        return methods

    @property
    def related_cve_ids(self) -> List[str]:
        return self.get_related_cve_ids()
    
    @property
    def related_capec_attack_pattern_ids(self) -> List[str]:
        return self.get_related_capec_attack_pattern_ids()

    def is_stable(self) -> bool:
        return self.status == 'Stable'

    def is_draft(self) -> bool:
        return self.status == 'Draft'

    def is_deprecated(self) -> bool:
        return self.status == 'Deprecated'
    
    def is_incomplete(self) -> bool:
        return self.status == 'Incomplete'
    
    def related_to_confidentiality(self) -> bool:
        return any(c.related_to_confidentiality() for c in self.common_consequences)
    
    def related_to_integrity(self) -> bool:
        return any(c.related_to_integrity() for c in self.common_consequences)

    def related_to_availability(self) -> bool:
        return any(c.related_to_availability() for c in self.common_consequences)
    
    def related_to_access_control(self) -> bool:
        return any(c.related_to_access_control() for c in self.common_consequences)
    
    def related_to_non_repudiation(self) -> bool:
        return any(c.related_to_non_repudiation() for c in self.common_consequences)
    
    def related_to_authentication(self) -> bool:
        return any(c.related_to_authentication() for c in self.common_consequences)
    
    def related_to_authorization(self) -> bool:
        return any(c.related_to_authorization() for c in self.common_consequences)
     
    def related_to_denial_of_service(self) -> bool:
        return any(c.related_to_denial_of_service() for c in self.common_consequences)
    
    def related_to_memory(self) -> bool:
        return any(c.related_to_memory() for c in self.common_consequences)
    
    def get_related_cve_ids(self) -> List[str]:
        cve_ids = set()
        for eg in self.observed_examples:
            if eg.is_cve_reference():
                cve_ids.add(eg.reference)
        return sorted(cve_ids)
    
    def get_related_capec_attack_pattern_ids(self) -> List[str]:
        return sorted(self.related_attack_patterns)


@dataclass()
class TaxonomyMapping:
    taxonomy_name: str
    entry_id: Optional[str]
    entry_name: Optional[str]


@dataclass()
class ExternalReference:
    id: str
    title: str
    publication_year: Optional[int]
    publication_month: Optional[int]
    publication_day: Optional[int]
    publication_date: Optional[datetime.date]
    publisher: Optional[str]
    url: Optional[str]
    url_date: Optional[datetime.date]


@dataclass()
class WeaknessCatalog:
    name: str
    version: str
    date: datetime.date
    weaknesses: List[Weakness]
    external_references: List[ExternalReference]

    def __iter__(self) -> Iterator[Weakness]:
        yield from self.weaknesses
