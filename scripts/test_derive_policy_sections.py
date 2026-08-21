#!/usr/bin/env python3
"""Tests for the policy-section derivation and the vendored pin table.

    python3 -m unittest discover -s scripts -p 'test_*.py'

The derivation decides what the compiler rejects, so the parts of it that used to
be wrong are pinned here: the nesting the corpus scan reads, the conflict it is
required to stop on, and the two records it has to keep saying the same thing.
"""

import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import derive_policy_sections as derive  # noqa: E402
import vendored  # noqa: E402

# The derived policy names the scan is given. The opaque containers are policy
# names too, which is what keeps their children out of the section.
NAMES = {
    "set-body", "rate-limit", "trace", "set-method", "set-header",
    "send-one-way-request", "send-request", "return-response", "set-variable",
}


def document(body):
    return f"<policies>{body}</policies>"


class SectionUses(unittest.TestCase):
    """What the corpus scan reports as a use of a policy IN a section."""

    def test_direct_child_of_a_section_is_a_section_level_use(self):
        uses = derive.section_uses(document("<on-error><set-body>x</set-body></on-error>"), NAMES)
        self.assertIn(("set-body", "on-error"), uses)

    def test_a_policys_own_children_are_not_section_level_uses(self):
        # The shape Log_errors_to_Stackify.policy.xml has, and the reason the flat
        # scan needed a hand-written excuse for (set-body, on-error).
        uses = derive.section_uses(
            document(
                "<on-error><send-one-way-request mode='new'>"
                "<set-method>POST</set-method><set-body>x</set-body>"
                "</send-one-way-request></on-error>"
            ),
            NAMES,
        )
        # The wrapper is in the section; what it wraps is in the wrapper.
        self.assertEqual({("send-one-way-request", "on-error")}, uses)

    def test_control_flow_passes_the_section_through(self):
        # A <rate-limit> inside a <choose> in <outbound> still runs outbound, which
        # is what the compiler holds it to.
        for body in (
            "<outbound><choose><when condition='@(true)'><rate-limit/></when></choose></outbound>",
            "<outbound><choose><otherwise><rate-limit/></otherwise></choose></outbound>",
            "<outbound><retry count='1'><rate-limit/></retry></outbound>",
            "<outbound><wait for='all'><choose><when condition='@(true)'>"
            "<rate-limit/></when></choose></wait></outbound>",
        ):
            with self.subTest(body=body):
                self.assertIn(("rate-limit", "outbound"), derive.section_uses(document(body), NAMES))

    def test_a_direct_use_is_reported_even_where_a_nested_one_exists(self):
        # The regression the pair-keyed excuse list could not catch: one snippet
        # nesting <set-body> under a policy, another putting it in the section.
        uses = derive.section_uses(
            document(
                "<on-error><send-one-way-request mode='new'><set-body>x</set-body>"
                "</send-one-way-request><set-body>y</set-body></on-error>"
            ),
            NAMES,
        )
        self.assertIn(("set-body", "on-error"), uses)

    def test_elements_outside_the_vocabulary_do_not_nest(self):
        # `List<string>` in an expression is a <string> tag with no closer. It must
        # not swallow the <set-body> that follows it.
        uses = derive.section_uses(
            document(
                "<inbound><set-variable name='v' value='@(new List<string>())'/>"
                "<set-body>x</set-body></inbound>"
            ),
            NAMES,
        )
        self.assertIn(("set-body", "inbound"), uses)

    def test_a_commented_out_policy_is_not_a_use(self):
        uses = derive.section_uses(
            document("<on-error><!-- <set-body>x</set-body> --></on-error>"), NAMES
        )
        self.assertEqual(set(), uses)

    def test_a_self_closing_policy_does_not_stay_open(self):
        uses = derive.section_uses(
            document("<inbound><rate-limit calls='1' renewal-period='60'/><set-body>x</set-body></inbound>"),
            NAMES,
        )
        self.assertEqual({("rate-limit", "inbound"), ("set-body", "inbound")}, uses)

    def test_closing_what_was_never_opened_is_an_error_not_a_guess(self):
        with self.assertRaises(SystemExit):
            derive.section_uses(document("<inbound></retry></inbound>"), NAMES)

    def test_an_element_left_open_is_an_error_not_a_guess(self):
        with self.assertRaises(SystemExit):
            derive.section_uses("<policies><inbound><choose><set-body>x</set-body>", NAMES)

    def test_a_tag_that_lost_its_closer_recovers_at_the_enclosing_one(self):
        # Set_cache_duration_using_response_cache_control_header.policy.xml puts a
        # `"` inside a `"`-delimited attribute, so <cache-store> never sees its own
        # closer and </outbound> is what recovers. The elements after it must still
        # be read against the section, not against the tag that stayed open.
        uses = derive.section_uses(
            document("<outbound><send-request><set-body>x</set-body></outbound>"), NAMES
        )
        self.assertEqual({("send-request", "outbound")}, uses)


class Widen(unittest.TestCase):
    """The classification a corpus/page disagreement is required to stop on."""

    def pages(self):
        return {"trace": ["inbound", "backend", "outbound"], "set-body": ["inbound", "backend", "outbound"]}

    def test_a_classified_pair_widens_the_page(self):
        with mock.patch.object(
            derive, "corpus_pairs", return_value={("trace", "on-error"): ["Log_errors_to_Stackify.policy.xml"]}
        ):
            derived = self.pages()
            widened = derive.widen(derived)
        self.assertEqual(["inbound", "backend", "outbound", "on-error"], derived["trace"])
        self.assertEqual({"trace": ["on-error"]}, widened)

    def test_an_unclassified_pair_stops_the_derivation(self):
        # What used to be answered by a pair-keyed excuse and silently dropped.
        pairs = {
            ("trace", "on-error"): ["Log_errors_to_Stackify.policy.xml"],
            ("set-body", "on-error"): ["Some_New_Snippet.policy.xml"],
        }
        with mock.patch.object(derive, "corpus_pairs", return_value=pairs):
            with self.assertRaises(SystemExit) as raised:
                derive.widen(self.pages())
        self.assertIn("CORPUS_WIDENS", str(raised.exception))
        self.assertIn("set-body", str(raised.exception))

    def test_a_widening_whose_witness_left_the_corpus_stops_the_derivation(self):
        pairs = {("trace", "on-error"): ["Some_Other_Snippet.policy.xml"]}
        with mock.patch.object(derive, "corpus_pairs", return_value=pairs):
            with self.assertRaises(SystemExit) as raised:
                derive.widen(self.pages())
        self.assertIn("Log_errors_to_Stackify.policy.xml", str(raised.exception))

    def test_a_widening_the_pages_caught_up_with_stops_the_derivation(self):
        with mock.patch.object(derive, "corpus_pairs", return_value={}):
            with self.assertRaises(SystemExit) as raised:
                derive.widen(self.pages())
        self.assertIn("no longer", str(raised.exception))

    def test_a_pair_the_page_already_documents_is_not_a_widening(self):
        with mock.patch.object(
            derive,
            "corpus_pairs",
            return_value={
                ("trace", "on-error"): ["Log_errors_to_Stackify.policy.xml"],
                ("set-body", "inbound"): ["Anything.xml"],
            },
        ):
            self.assertEqual({"trace": ["on-error"]}, derive.widen(self.pages()))


class Records(unittest.TestCase):
    """The two records the derivation writes, and what has to be true of both."""

    def setUp(self):
        self.inventory, self.record = derive.derive()

    def test_every_ledger_policy_is_derived(self):
        # authentication-oauth2 was absent from the derivation, so the ledger kept
        # a hand-written `backend` while the compiler held it to no section at all.
        ledger = {item["name"] for item in self.inventory["policies"]}
        self.assertEqual(set(), ledger - set(self.record["policies"]))

    def test_the_two_records_agree_on_every_policy(self):
        inventory, _ = derive.rendered(self.inventory, self.record)
        for item in self.inventory["policies"]:
            self.assertEqual(
                self.record["policies"][item["name"]],
                item["sections"],
                f"{item['name']} differs between the compiler's record and the ledger",
            )
        self.assertTrue(inventory)

    def test_a_ledger_entry_with_no_derivation_stops_the_render(self):
        self.inventory["policies"].append({"name": "invented-policy", "status": "implemented"})
        with self.assertRaises(SystemExit) as raised:
            derive.rendered(self.inventory, self.record)
        self.assertIn("invented-policy", str(raised.exception))

    def test_the_pageless_names_carry_the_sections_they_are_held_to(self):
        self.assertEqual(list(derive.SECTIONS), self.record["policies"]["base"])
        self.assertEqual(["inbound"], self.record["policies"]["authentication-oauth2"])
        for name in derive.NO_REFERENCE_PAGE:
            self.assertNotIn(name, derive.SECTIONLESS)

    def test_the_resolver_policies_are_held_to_no_section(self):
        for name in derive.SECTIONLESS:
            self.assertEqual([], self.record["policies"][name], name)

    def test_aliases_follow_the_page_their_content_moved_to(self):
        for alias, page in derive.ALIASES.items():
            self.assertEqual(self.record["policies"][page], self.record["policies"][alias], alias)

    def test_the_record_states_the_commit_it_was_read_from(self):
        self.assertEqual(vendored.pin("policy-reference/*.md"), self.record["commit"])
        self.assertEqual(vendored.pin("policy-snippets/*.xml"), self.record["snippets"]["commit"])


class Corpus(unittest.TestCase):
    """The vendored snippets themselves, read the way the derivation reads them."""

    def test_every_vendored_snippet_balances(self):
        # The scan raises rather than guessing, so this is what stands between a
        # corpus refresh and a table derived from a crooked read.
        names = set(derive.derive()[1]["policies"])
        for snippet in sorted(derive.SNIPPETS.glob("*.xml")):
            with self.subTest(snippet=snippet.name):
                derive.section_uses(snippet.read_text(), names)

    def test_the_stackify_snippet_is_read_the_way_it_is_classified(self):
        # Both halves of the one hand-classified pair, read off the real file.
        names = set(derive.derive()[1]["policies"])
        uses = derive.section_uses(
            (derive.SNIPPETS / "Log_errors_to_Stackify.policy.xml").read_text(), names
        )
        self.assertIn(("trace", "on-error"), uses)
        self.assertNotIn(("set-body", "on-error"), uses)
        self.assertNotIn(("set-method", "on-error"), uses)


class VendoredPins(unittest.TestCase):
    """The pin table every derivation states its provenance from."""

    def test_the_table_is_read_not_transcribed(self):
        table = vendored.pins()
        self.assertIn("policy-reference/*.md", table)
        self.assertIn("policy-snippets/*.xml", table)
        for pattern, commit in table.items():
            self.assertRegex(commit, r"^[0-9a-f]{40}$", pattern)

    def test_an_unpinned_pattern_is_an_error_not_a_default(self):
        with self.assertRaises(SystemExit) as raised:
            vendored.pin("policy-reference/*.txt")
        self.assertIn("no pin", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
