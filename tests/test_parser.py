import dataclasses
import datetime
import json
import os
import textwrap
import unittest
import xml.etree.ElementTree as ET

from cwe import parser
from cwe.util import JSONEncoder
from tests import audit

EXAMPLE_FILES = [
    path
    for path in (os.environ.get("CWE_XML_PATH"), "examples/cwec_latest.xml")
    if path and os.path.exists(path)
]

CONTENT_HISTORY = '''
    <Content_History>
      <Submission>
        <Submission_Name>Ann</Submission_Name><Submission_Name>Bob</Submission_Name>
        <Submission_Organization>MITRE</Submission_Organization><Submission_Date>2006-07-19</Submission_Date>
        <Submission_Version>Draft 3</Submission_Version><Submission_ReleaseDate>2006-07-20</Submission_ReleaseDate>
        <Submission_Comment>Initial.</Submission_Comment>
      </Submission>
      <Modification>
        <Modification_Name>CWE Content Team</Modification_Name><Modification_Organization>MITRE</Modification_Organization>
        <Modification_Date>2008-09-08</Modification_Date><Modification_Version>1.0</Modification_Version>
        <Modification_ReleaseDate>2008-09-09</Modification_ReleaseDate><Modification_Importance>Critical</Modification_Importance>
        <Modification_Comment>updated Relationships</Modification_Comment>
      </Modification>
      <Contribution Type="Feedback">
        <Contribution_Name>Cy</Contribution_Name><Contribution_Organization>Org</Contribution_Organization>
        <Contribution_Date>2021-05-28</Contribution_Date><Contribution_Version>4.5</Contribution_Version>
        <Contribution_ReleaseDate>2021-07-20</Contribution_ReleaseDate><Contribution_Comment>Suggested.</Contribution_Comment>
      </Contribution>
      <Previous_Entry_Name Date="2008-04-11" Version="1.4">Old Name</Previous_Entry_Name>
    </Content_History>
'''

COMMON = '''
    <References><Reference External_Reference_ID="REF-44" Section="Sin 8"/><Reference External_Reference_ID="REF-7"/></References>
    <Mapping_Notes>
      <Usage>Allowed-with-Review</Usage><Rationale>Because.</Rationale>
      <Comments><h:p>Read</h:p><h:p>carefully.</h:p></Comments>
      <Reasons><Reason Type="Abstraction"/><Reason Type="Other"/></Reasons>
      <Suggestions><Suggestion CWE_ID="20" Comment="Consider this."/></Suggestions>
    </Mapping_Notes>
    <Notes>
      <Note Type="Maintenance" Version="5.0" ReleaseDate="2026-10-28">Plain
          note.</Note>
      <Note Type="Relationship"><h:p>Rich</h:p><h:ul><h:li>note</h:li></h:ul></Note>
    </Notes>
''' + CONTENT_HISTORY

CATALOG = textwrap.dedent('''\
    <?xml version="1.0" encoding="UTF-8"?>
    <Weakness_Catalog Name="CWE" Version="5.0" Date="2026-10-28" xmlns="http://cwe.mitre.org/cwe-8" xmlns:h="http://www.w3.org/1999/xhtml">
      <Weaknesses>
        <Weakness ID="395" Name="Example" Abstraction="Base" Structure="Simple" Status="Draft" Diagram="/data/images/CWE-395.png">
          <Description>Plain
              description.</Description>
          <Extended_Description>
            <h:p>First.</h:p>
            <h:ol><h:li>One</h:li><h:li>Two<h:ul><h:li>Nested</h:li></h:ul></h:li></h:ol>
          </Extended_Description>
          <Related_Weaknesses>
            <Related_Weakness Nature="ChildOf" CWE_ID="705" View_ID="1000" Ordinal="Primary">
              <Dimensions><Dimension Type="Behavior-Type">Handling</Dimension></Dimensions>
            </Related_Weakness>
            <Related_Weakness Nature="CanPrecede" CWE_ID="476" View_ID="1000" Chain_ID="690"/>
          </Related_Weaknesses>
          <Weakness_Ordinalities>
            <Weakness_Ordinality><Ordinality>Primary</Ordinality><Description>Standalone.</Description></Weakness_Ordinality>
            <Weakness_Ordinality><Ordinality>Resultant</Ordinality></Weakness_Ordinality>
          </Weakness_Ordinalities>
          <Applicable_Platforms>
            <Language Name="Java" Prevalence="Often"><Note>Mostly.</Note></Language>
            <Language Class="Memory-Unsafe" Prevalence="Undetermined"/>
            <Operating_System Class="Not OS-Specific" Prevalence="Undetermined"/>
            <Technology Class="Web Based" Prevalence="Sometimes"/>
          </Applicable_Platforms>
          <Background_Details><Background_Detail>Background.</Background_Detail></Background_Details>
          <Alternate_Terms>
            <Alternate_Term><Term>NPE</Term><Role>Acronym</Role><Role>Common-Name</Role><Description>Short.</Description></Alternate_Term>
          </Alternate_Terms>
          <Modes_Of_Introduction>
            <Introduction>
              <Phase>Implementation</Phase>
              <Note>
                <h:p>Programmers typically catch NullPointerException under three circumstances:</h:p>
                <h:ul>
                  <h:li>The program contains a null pointer dereference.</h:li>
                  <h:li>The program explicitly throws a NullPointerException.</h:li>
                </h:ul>
                <h:p>Of these three circumstances, only the last is acceptable.</h:p>
              </Note>
            </Introduction>
            <Introduction><Phase>Design</Phase><Note>Plain note.</Note></Introduction>
            <Introduction><Custom_Phase Domain="AI">Training</Custom_Phase></Introduction>
          </Modes_Of_Introduction>
          <Likelihood_Of_Exploit>Medium</Likelihood_Of_Exploit>
          <Common_Consequences>
            <Consequence><Scope>Integrity</Scope><Scope>Availability</Scope><Impact>DoS</Impact><Likelihood>Unknown</Likelihood><Note><h:p>A</h:p><h:p>B</h:p></Note></Consequence>
            <Consequence><Scope>Integrity</Scope><Scope>Availability</Scope><Impact>DoS</Impact><Note><h:p>A</h:p><h:p>B</h:p></Note></Consequence>
          </Common_Consequences>
          <Detection_Methods>
            <Detection_Method Detection_Method_ID="DM-1">
              <Method>Manual Analysis</Method>
              <Phase>Testing</Phase>
              <Description>
                <h:p>According to SOAR:</h:p>
                <h:div style="margin-left:1em;"><h:div>Cost effective:</h:div><h:ul><h:li>Fuzzing</h:li></h:ul></h:div>
              </Description>
              <Effectiveness>High</Effectiveness>
              <Effectiveness_Notes>Usually.</Effectiveness_Notes>
            </Detection_Method>
          </Detection_Methods>
          <Potential_Mitigations>
            <Mitigation Mitigation_ID="MIT-4">
              <Phase>Implementation</Phase><Phase>Architecture and Design</Phase>
              <Custom_Phase Domain="Hardware">Hardware Architecture</Custom_Phase>
              <Strategy>Refactoring</Strategy>
              <Description><h:p>Do not catch it.</h:p></Description>
              <Effectiveness>Moderate</Effectiveness><Effectiveness_Notes>Depends.</Effectiveness_Notes>
            </Mitigation>
          </Potential_Mitigations>
          <Demonstrative_Examples>
            <Demonstrative_Example Demonstrative_Example_ID="DX-1">
              <Intro_Text>The following code catches the exception.</Intro_Text>
              <Example_Code Nature="Bad" Language="Java">
                <h:div>try {<h:div style="margin-left:1em;">
                    mysteryMethod();<h:br/>
                    <h:br/><h:i>// second call</h:i><h:br/>other();</h:div>}<h:br/>catch (NullPointerException npe) {<h:div style="margin-left:1em;">
                    <h:div style="margin-left:1em;">deep();</h:div>
                  </h:div>}</h:div>
              </Example_Code>
              <Body_Text>This is <h:b>bad</h:b>.</Body_Text>
              <Example_Code Nature="Good">
                  line one
                    line two
              </Example_Code>
              <Body_Text>Done.</Body_Text>
              <References><Reference External_Reference_ID="REF-9"/></References>
            </Demonstrative_Example>
          </Demonstrative_Examples>
          <Observed_Examples>
            <Observed_Example><Reference>CVE-2024-47833</Reference><Description>Example.</Description><Link>https://www.cve.org/CVERecord?id=CVE-2024-47833</Link><Rationale>Chain</Rationale></Observed_Example>
          </Observed_Examples>
          <Functional_Areas><Functional_Area>Error Handling</Functional_Area></Functional_Areas>
          <Affected_Resources><Affected_Resource>Memory</Affected_Resource></Affected_Resources>
          <Taxonomy_Mappings>
            <Taxonomy_Mapping Taxonomy_Name="CERT"><Entry_ID>ERR08-J</Entry_ID><Entry_Name>Do not catch</Entry_Name><Mapping_Fit>Exact</Mapping_Fit></Taxonomy_Mapping>
            <Taxonomy_Mapping Taxonomy_Name="PLOVER"><Entry_Name>Only a name</Entry_Name></Taxonomy_Mapping>
          </Taxonomy_Mappings>
          <Related_Attack_Patterns><Related_Attack_Pattern CAPEC_ID="100"/><Related_Attack_Pattern CAPEC_ID="7"/></Related_Attack_Patterns>
          <Dimensions><Dimension Type="Behavior-Type">Catch</Dimension></Dimensions>
          <Technical_Nuance><h:p>Nuance.</h:p></Technical_Nuance>
''' + COMMON + '''
        </Weakness>
        <Weakness ID="1" Name="Minimal" Abstraction="Class" Structure="Simple" Status="Incomplete">
          <Description>Only the required fields.</Description>
        </Weakness>
      </Weaknesses>
      <Groupings>
        <Grouping ID="1" Name="Group" Status="Draft">
          <Summary>Summary.</Summary>
          <Relationships><Has_Member CWE_ID="395" View_ID="699"/><Has_Member CWE_ID="2" View_ID="699"/></Relationships>
          <Taxonomy_Mappings><Taxonomy_Mapping Taxonomy_Name="WASC"><Entry_ID>14</Entry_ID></Taxonomy_Mapping></Taxonomy_Mappings>
''' + COMMON + '''
        </Grouping>
      </Groupings>
      <Views>
        <View ID="1000" Name="View" Type="Graph" Status="Draft">
          <Objective><h:p>One.</h:p><h:p>Two.</h:p></Objective>
          <Audience>
            <Stakeholder><Type>Educators</Type><Description>Teach.</Description></Stakeholder>
            <Stakeholder><Type>Software Developers</Type></Stakeholder>
          </Audience>
          <Members><Has_Member CWE_ID="395" View_ID="1000"/></Members>
''' + COMMON + '''
        </View>
        <View ID="1001" Name="Implicit" Type="Implicit" Status="Draft">
          <Filter>/Weakness_Catalog/Weaknesses/Weakness[@Status='Draft']</Filter>
        </View>
      </Views>
      <External_References>
        <External_Reference Reference_ID="REF-44">
          <Author>Zed</Author><Author>Amy</Author><Author/>
          <Title>24 Deadly Sins</Title><Edition>1st Edition</Edition><Publication>Journal</Publication>
          <Publication_Year>2019</Publication_Year><Publication_Month>--09</Publication_Month><Publication_Day>---07</Publication_Day>
          <Publisher>McGraw-Hill</Publisher><URL>https://example.com/a</URL><URL_Date>2025-07-25</URL_Date>
          <Alt_URL>https://example.com/b</Alt_URL><Alt_URL_Date>2026-10-22</Alt_URL_Date>
          <Access_Restrictions>Proprietary-Subscription</Access_Restrictions>
          <Media_Type>Video</Media_Type><Rationale>Early-Publication</Rationale><Rationale>Influential/Newsworthy</Rationale>
        </External_Reference>
        <External_Reference Reference_ID="REF-7"><Title>Year only</Title><Publication_Year>2019</Publication_Year></External_Reference>
        <External_Reference Reference_ID="REF-8"><Title>Year and month</Title><Publication_Year>2019</Publication_Year><Publication_Month>--09</Publication_Month></External_Reference>
        <External_Reference Reference_ID="REF-9"><Title>No date</Title></External_Reference>
      </External_References>
    </Weakness_Catalog>
''')


def render(xhtml: str, renderer=parser.xhtml_to_markdown) -> str:
    return renderer(ET.fromstring(f'<Note xmlns:xhtml="http://www.w3.org/1999/xhtml">{xhtml}</Note>'))


class XhtmlToMarkdownTestCase(unittest.TestCase):
    def test_order_of_mixed_blocks_is_preserved(self):
        result = render('<xhtml:p>Before</xhtml:p><xhtml:ul><xhtml:li>A</xhtml:li><xhtml:li>B</xhtml:li></xhtml:ul><xhtml:p>After</xhtml:p>')
        self.assertEqual(result, 'Before\n\n- A\n- B\n\nAfter')

    def test_ordered_and_nested_lists(self):
        result = render('<xhtml:ol><xhtml:li>One</xhtml:li><xhtml:li>Two<xhtml:ul><xhtml:li>Nested</xhtml:li></xhtml:ul></xhtml:li></xhtml:ol>')
        self.assertEqual(result, '1. One\n2. Two\n   - Nested')

    def test_text_outside_of_block_elements_is_kept(self):
        self.assertEqual(render('Lead in:<xhtml:ul><xhtml:li>A</xhtml:li></xhtml:ul>trailing'), 'Lead in:\n\n- A\n\ntrailing')

    def test_whitespace_is_collapsed(self):
        self.assertEqual(render('<xhtml:p>\n  a\n     b  </xhtml:p>'), 'a b')

    def test_inline_elements(self):
        self.assertEqual(render('<xhtml:p>x<xhtml:sup>6</xhtml:sup> is <xhtml:b>bold</xhtml:b></xhtml:p>'), 'x^6 is bold')
        self.assertEqual(render('<xhtml:p>a<xhtml:br/>b</xhtml:p>'), 'a\nb')
        self.assertEqual(render('<xhtml:img src="/a.png" alt="A"/>'), '![A](/a.png)')

    def test_table(self):
        result = render('<xhtml:table><xhtml:tr><xhtml:th>A</xhtml:th><xhtml:th>B|C</xhtml:th></xhtml:tr><xhtml:tr><xhtml:td>1</xhtml:td><xhtml:td>2</xhtml:td></xhtml:tr></xhtml:table>')
        self.assertEqual(result, '| A | B\\|C |\n| --- | --- |\n| 1 | 2 |')


class XhtmlToCodeTestCase(unittest.TestCase):
    def test_line_breaks_and_indentation(self):
        result = render(
            '<xhtml:div>if (a) {<xhtml:div style="margin-left:1em;">b();<xhtml:br/>\n   <xhtml:br/>c();'
            '<xhtml:div style="margin-left:1em;">d();</xhtml:div></xhtml:div>}</xhtml:div>',
            parser.xhtml_to_code,
        )
        self.assertEqual(result, 'if (a) {\n    b();\n\n    c();\n        d();\n}')

    def test_text_outside_of_elements_and_inline_markup(self):
        result = render('first();<xhtml:br/><xhtml:i>// comment</xhtml:i> second();', parser.xhtml_to_code)
        self.assertEqual(result, 'first();\n// comment second();')

    def test_div_without_margin_does_not_indent(self):
        self.assertEqual(render('<xhtml:div>a<xhtml:div>b</xhtml:div></xhtml:div>', parser.xhtml_to_code), 'a\nb')


class ParserTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = ET.fromstring(CATALOG)
        cls.catalog = parser.parse_weakness_catalog(cls.root)
        cls.weakness = cls.catalog.weaknesses[0]

    def test_catalog(self):
        self.assertEqual((self.catalog.name, self.catalog.version), ('CWE', '5.0'))
        self.assertEqual(self.catalog.date, datetime.date(2026, 10, 28))
        self.assertIs(type(self.catalog.date), datetime.date)
        counts = [len(x) for x in (self.catalog.weaknesses, self.catalog.groupings, self.catalog.views, self.catalog.external_references)]
        self.assertEqual(counts, [2, 1, 2, 4])

    def test_weakness_attributes_and_text(self):
        w = self.weakness
        self.assertEqual((w.id, w.name, w.abstraction, w.structure, w.status), ('395', 'Example', 'Base', 'Simple', 'Draft'))
        self.assertEqual(w.diagram, '/data/images/CWE-395.png')
        self.assertEqual(w.description, 'Plain description.')
        self.assertEqual(w.extended_description, 'First.\n\n1. One\n2. Two\n   - Nested')
        self.assertEqual(w.background_details, ['Background.'])
        self.assertEqual(w.technical_nuance, 'Nuance.')
        self.assertEqual(w.likelihood_of_exploitation, 'Medium')
        self.assertEqual(w.functional_areas, ['Error Handling'])
        self.assertEqual(w.affected_resources, ['Memory'])
        self.assertEqual(w.related_attack_patterns, ['100', '7'])
        self.assertEqual([(d.type, d.value) for d in w.dimensions], [('Behavior-Type', 'Catch')])

    def test_minimal_weakness(self):
        w = self.catalog.weaknesses[1]
        self.assertEqual(w.description, 'Only the required fields.')
        self.assertIsNone(w.mapping_notes)
        empty = [f.name for f in dataclasses.fields(w) if getattr(w, f.name) == []]
        self.assertEqual(len(empty), 22)

    def test_related_weaknesses(self):
        child_of, can_precede = self.weakness.related_weaknesses
        self.assertEqual((child_of.cwe_id, child_of.view_id, child_of.nature, child_of.ordinal), ('705', '1000', 'ChildOf', 'Primary'))
        self.assertEqual([(d.type, d.value) for d in child_of.dimensions], [('Behavior-Type', 'Handling')])
        self.assertEqual((can_precede.chain_id, can_precede.ordinal), ('690', None))
        self.assertEqual(self.weakness.child_of, ['705'])
        self.assertEqual(self.weakness.can_precede, ['476'])

    def test_weakness_ordinalities(self):
        result = [(o.ordinality, o.description) for o in self.weakness.weakness_ordinalities]
        self.assertEqual(result, [('Primary', 'Standalone.'), ('Resultant', None)])

    def test_applicable_platforms(self):
        result = [(p.type, p.name, p.platform_class, p.prevalence, p.note) for p in self.weakness.applicable_platforms]
        self.assertEqual(result, [
            ('Language', 'Java', None, 'Often', 'Mostly.'),
            ('Language', None, 'Memory-Unsafe', 'Undetermined', None),
            ('Operating System', None, 'Not OS-Specific', 'Undetermined', None),
            ('Technology', None, 'Web Based', 'Sometimes', None),
        ])

    def test_alternate_terms(self):
        term, = self.weakness.alternate_terms
        self.assertEqual((term.name, term.description, term.roles), ('NPE', 'Short.', ['Acronym', 'Common-Name']))

    def test_modes_of_introduction(self):
        xhtml, plain, custom = self.weakness.modes_of_introduction
        self.assertEqual(xhtml.note, '\n\n'.join([
            'Programmers typically catch NullPointerException under three circumstances:',
            '- The program contains a null pointer dereference.\n- The program explicitly throws a NullPointerException.',
            'Of these three circumstances, only the last is acceptable.',
        ]))
        self.assertEqual((plain.phase, plain.note), (['Design'], 'Plain note.'))
        self.assertEqual((custom.phase, custom.note), ([], None))
        self.assertEqual([(p.name, p.domain) for p in custom.custom_phases], [('Training', 'AI')])

    def test_consequences(self):
        unknown, unspecified = self.weakness.common_consequences
        self.assertEqual(unknown.scope, ['Availability', 'Integrity'])
        self.assertEqual(unknown.note, 'A\n\nB')
        self.assertIsNone(unknown.likelihood)
        self.assertEqual(unknown, unspecified)

    def test_detection_methods(self):
        d, = self.weakness.detection_methods
        self.assertEqual((d.id, d.name, d.phase, d.effectiveness, d.effectiveness_notes), ('DM-1', 'Manual Analysis', ['Testing'], 'High', 'Usually.'))
        self.assertEqual(d.description, 'According to SOAR:\n\nCost effective:\n\n- Fuzzing')

    def test_mitigations(self):
        m, = self.weakness.potential_mitigations
        self.assertEqual((m.id, m.phase, m.strategy), ('MIT-4', ['Architecture and Design', 'Implementation'], 'Refactoring'))
        self.assertEqual((m.description, m.effectiveness, m.effectiveness_notes), ('Do not catch it.', 'Moderate', 'Depends.'))
        self.assertEqual([(p.name, p.domain) for p in m.custom_phases], [('Hardware Architecture', 'Hardware')])

    def test_demonstrative_examples(self):
        example, = self.weakness.demonstrative_examples
        self.assertEqual((example.id, example.intro_text), ('DX-1', 'The following code catches the exception.'))
        self.assertEqual([r.external_reference_id for r in example.references], ['REF-9'])
        self.assertEqual([(b.type, b.nature, b.language) for b in example.body], [
            ('code', 'Bad', 'Java'), ('text', None, None), ('code', 'Good', None), ('text', None, None),
        ])
        self.assertEqual(example.body[0].content, '\n'.join([
            'try {',
            '    mysteryMethod();',
            '',
            '    // second call',
            '    other();',
            '}',
            'catch (NullPointerException npe) {',
            '        deep();',
            '}',
        ]))
        self.assertEqual(example.body[1].content, 'This is bad.')
        self.assertEqual(example.body[2].content, 'line one\n  line two')

    def test_observed_examples(self):
        e, = self.weakness.observed_examples
        self.assertEqual((e.reference, e.description, e.rationales), ('CVE-2024-47833', 'Example.', ['Chain']))
        self.assertEqual(e.link, 'https://www.cve.org/CVERecord?id=CVE-2024-47833')
        self.assertTrue(e.is_cve_id())

    def test_taxonomy_mappings(self):
        result = [(t.taxonomy_name, t.entry_id, t.entry_name, t.mapping_fit) for t in self.weakness.taxonomy_mappings]
        self.assertEqual(result, [('CERT', 'ERR08-J', 'Do not catch', 'Exact'), ('PLOVER', None, 'Only a name', None)])

    def test_common_fields(self):
        for item in (self.weakness, self.catalog.groupings[0], self.catalog.views[0]):
            with self.subTest(type(item).__name__):
                self.assertEqual([(r.external_reference_id, r.section) for r in item.references], [('REF-44', 'Sin 8'), ('REF-7', None)])
                self.assertEqual(item.external_reference_ids, ['REF-44', 'REF-7'])

                m = item.mapping_notes
                self.assertEqual((m.usage, m.rationale, m.comments, m.reasons), ('Allowed-with-Review', 'Because.', 'Read\n\ncarefully.', ['Abstraction', 'Other']))
                self.assertEqual([(s.cwe_id, s.comment) for s in m.suggestions], [('20', 'Consider this.')])

                plain, rich = item.notes
                self.assertEqual((plain.note_type, plain.value, plain.version, plain.release_date), ('Maintenance', 'Plain note.', '5.0', '2026-10-28'))
                self.assertEqual((rich.note_type, rich.value, rich.version), ('Relationship', 'Rich\n\n- note', None))

                s, = item.submission_history
                self.assertEqual((s.names, s.organization, s.date, s.version, s.release_date, s.comment), (['Ann', 'Bob'], 'MITRE', '2006-07-19', 'Draft 3', '2006-07-20', 'Initial.'))
                m, = item.modification_history
                self.assertEqual((m.name, m.organization, m.date, m.version, m.release_date, m.comment, m.importance), ('CWE Content Team', 'MITRE', '2008-09-08', '1.0', '2008-09-09', 'updated Relationships', 'Critical'))
                c, = item.contribution_history
                self.assertEqual((c.type, c.names, c.organization, c.date, c.version, c.release_date, c.comment), ('Feedback', ['Cy'], 'Org', '2021-05-28', '4.5', '2021-07-20', 'Suggested.'))
                p, = item.previous_entry_names
                self.assertEqual((p.name, p.date, p.version), ('Old Name', '2008-04-11', '1.4'))

    def test_grouping(self):
        g, = self.catalog.groupings
        self.assertEqual((g.id, g.name, g.status, g.description), ('1', 'Group', 'Draft', 'Summary.'))
        self.assertEqual([(m.cwe_id, m.view_id, m.nature) for m in g.members], [('395', '699', 'HasMember'), ('2', '699', 'HasMember')])
        self.assertEqual([(t.taxonomy_name, t.entry_id) for t in g.taxonomy_mappings], [('WASC', '14')])

    def test_categories_are_parsed_as_groupings(self):
        document = CATALOG.replace('Groupings>', 'Categories>').replace('<Grouping ', '<Category ').replace('</Grouping>', '</Category>')
        document = document.replace('http://cwe.mitre.org/cwe-8', 'http://cwe.mitre.org/cwe-7')
        self.assertEqual(parser.parse_weakness_catalog(ET.fromstring(document)), self.catalog)

    def test_views(self):
        graph, implicit = self.catalog.views
        self.assertEqual((graph.id, graph.name, graph.type, graph.status), ('1000', 'View', 'Graph', 'Draft'))
        self.assertEqual(graph.objective, 'One.\n\nTwo.')
        self.assertEqual([(s.type, s.description) for s in graph.audience], [('Educators', 'Teach.'), ('Software Developers', None)])
        self.assertEqual([(m.cwe_id, m.view_id, m.nature) for m in graph.members], [('395', '1000', 'HasMember')])
        self.assertIsNone(graph.filter)
        self.assertEqual(implicit.filter, "/Weakness_Catalog/Weaknesses/Weakness[@Status='Draft']")
        self.assertEqual((implicit.members, implicit.audience, implicit.mapping_notes), ([], [], None))

    def test_external_references(self):
        full, year, month, undated = self.catalog.external_references
        self.assertEqual((full.id, full.name, full.authors), ('REF-44', '24 Deadly Sins', ['Zed', 'Amy']))
        self.assertEqual((full.edition, full.publication, full.publisher), ('1st Edition', 'Journal', 'McGraw-Hill'))
        self.assertEqual((full.url, full.url_date, full.alt_url, full.alt_url_date), ('https://example.com/a', '2025-07-25', 'https://example.com/b', '2026-10-22'))
        self.assertEqual((full.access_restrictions, full.media_types, full.rationales), ('Proprietary-Subscription', ['Video'], ['Early-Publication', 'Influential/Newsworthy']))
        self.assertEqual([r.publication_date for r in (full, year, month, undated)], ['2019-09-07', '2019', '2019-09', None])

    def test_catalog_properties_deduplicate(self):
        self.assertEqual(len(self.catalog.consequences), 1)
        self.assertEqual(len(self.catalog.detection_methods), 1)

    def test_json_round_trip(self):
        document = json.loads(json.dumps(self.catalog, cls=JSONEncoder))
        self.assertEqual(document['date'], '2026-10-28')
        self.assertEqual(document['weaknesses'][0]['demonstrative_examples'][0]['body'][1], {'type': 'text', 'content': 'This is bad.'})

    def test_missing_required_values_are_rejected(self):
        for xml in (
            '<Weakness ID="1" Name="N" Abstraction="Base" Structure="Simple" Status="Draft"/>',
            '<Weakness ID="1" Name="N" Abstraction="Base" Structure="Simple"><Description>D</Description></Weakness>',
        ):
            with self.subTest(xml), self.assertRaises(Exception):
                parser.parse_weakness(ET.fromstring(xml))


class AuditTestCase(unittest.TestCase):
    def test_every_value_in_the_test_catalog_is_extracted(self):
        root = ET.fromstring(CATALOG)
        catalog = parser.parse_weakness_catalog(root)
        sections = zip(root, (catalog.weaknesses, catalog.groupings, catalog.views, catalog.external_references))
        results = [r for section, items in sections for e, item in zip(section, items) for r in audit.audit_item(e, item)]
        self.assertGreater(len(results), 250)
        self.assertEqual([r for r in results if not r[1]], [])

    def test_audit_detects_missing_values(self):
        root = ET.fromstring(CATALOG)
        weakness = parser.parse_weakness(root[0][0])
        weakness.notes.pop()
        weakness.related_weaknesses[1].chain_id = None
        weakness.demonstrative_examples[0].body[0].content = 'try {'
        missing = sorted(path for path, found, _ in audit.audit_item(root[0][0], weakness) if not found)
        self.assertEqual(missing, [
            'Weakness/Demonstrative_Examples/Demonstrative_Example/Example_Code (XHTML)',
            'Weakness/Notes/Note (XHTML)',
            'Weakness/Notes/Note/@Type',
            'Weakness/Related_Weaknesses/Related_Weakness/@Chain_ID',
        ])

    def test_every_value_in_the_example_files_is_extracted(self):
        if not EXAMPLE_FILES:
            self.skipTest('No CWE XML files are available (set CWE_XML_PATH)')
        for path in EXAMPLE_FILES:
            with self.subTest(path):
                summary, failures = audit.audit_file(path)
                self.assertGreater(len(summary), 150)
                self.assertEqual(failures, [])


if __name__ == '__main__':
    unittest.main()
