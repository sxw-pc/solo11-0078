"""Language-identity key preflight tests (Turkish/Azerbaijani casing).

Covers the four I-family letters, the decomposed I+U+0307 context, tr/az and
English mixing, missing/conflicting/unsupported language tags, NFC-vs-case
ordering, shared-index cross-language collisions, the two opt-in contracts,
and legacy-config compatibility.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
import unicodedata
from pathlib import Path

from charorder.artifacts import execute
from charorder.config import load_config
from charorder.engine import scan
from charorder.ingest import load_sources
from charorder.transforms import (
    TURKIC_LANGUAGES,
    UNIT_SEPARATOR,
    TransformTrace,
    _SOFT_DOTTED,
    apply_transform,
    apply_transform_traced,
    contains_turkic_sensitive_codepoints,
    make_target_key,
    turkic_casefold,
    turkic_lower,
    turkic_upper,
)
from charorder import UNICODE_VERSION
from charorder.models import TransformSpec
from charorder.verify import verify_run

from tests.support import (
    language_key,
    language_policy,
    minimal_config,
    write_config,
)

I = "I"          # U+0049
IDOT = "İ"       # U+0130
IDOTLESS = "ı"   # U+0131
i_ = "i"         # U+0069
DOT = "̇"      # U+0307


class TurkicMappingTests(unittest.TestCase):
    """Acceptance 1: mapping accuracy incl. full-string context."""

    def test_lower_splits_two_equivalence_classes(self) -> None:
        # I / ı -> dotless ı ; İ / i / I+U+0307 -> dotted i
        self.assertEqual(turkic_lower(I), IDOTLESS)
        self.assertEqual(turkic_lower(IDOTLESS), IDOTLESS)
        self.assertEqual(turkic_lower(IDOT), i_)
        self.assertEqual(turkic_lower(i_), i_)
        self.assertEqual(turkic_lower(I + DOT), i_)

    def test_decomposed_context_is_not_a_character_replace(self) -> None:
        # NFD form of İ is exactly I + U+0307.
        self.assertEqual(unicodedata.normalize("NFD", IDOT), I + DOT)
        self.assertEqual(turkic_lower(unicodedata.normalize("NFD", IDOT)), i_)
        # A naive replace('I','ı') would give 'ı̇' here; the context rule must
        # instead consume the dot.
        self.assertNotEqual(turkic_lower(I + DOT), IDOTLESS + DOT)

    def test_soft_dotted_dot_removal_context(self) -> None:
        # After_Soft_Dotted: j + U+0307 loses the dot on lowercasing.
        self.assertEqual(turkic_lower("J" + DOT), "j")
        # U+0131 is Soft_Dotted per PropList, so its combining dot is absorbed.
        self.assertEqual(turkic_lower(IDOTLESS + DOT), IDOTLESS)
        # U+0249 is not Soft_Dotted: the dot above survives.
        self.assertEqual(turkic_lower("Ɉ̇"), "ɉ̇")

    def test_upper_and_casefold(self) -> None:
        self.assertEqual(turkic_upper(i_), IDOT)
        self.assertEqual(turkic_upper(IDOTLESS), I)
        self.assertEqual(turkic_upper(I), I)
        # casefold keeps the Turkic I split but still folds e.g. ß.
        self.assertEqual(turkic_casefold(I), IDOTLESS)
        self.assertEqual(turkic_casefold(IDOT), i_)
        self.assertEqual(turkic_casefold("Straße"), "strasse")

    def test_neutral_python_mapping_is_demonstrably_different(self) -> None:
        # Locale-neutral lower maps capital I -> ASCII i, while the Turkic
        # context rule maps it to dotless U+0131.
        self.assertEqual(I.lower(), i_)
        self.assertEqual(turkic_lower(I), IDOTLESS)
        self.assertNotEqual(I.lower(), turkic_lower(I))
        # And the default lower leaves İ as i + U+0307, not plain i.
        self.assertEqual(IDOT.lower(), i_ + DOT)
        self.assertEqual(turkic_lower(IDOT), i_)

    def test_sensitive_codepoint_detects_decomposed_form(self) -> None:
        self.assertTrue(contains_turkic_sensitive_codepoints(I + DOT))
        self.assertTrue(contains_turkic_sensitive_codepoints(IDOT))
        self.assertFalse(contains_turkic_sensitive_codepoints("abc xyz"))
        # The letter "i" itself is part of the governed family.
        self.assertTrue(contains_turkic_sensitive_codepoints(i_))

    def test_unicode_data_version_and_soft_dotted_set_are_pinned(self) -> None:
        # The mapping contract is fixed to the bundled Unicode database so a
        # interpreter upgrade cannot silently change key equivalence classes.
        self.assertEqual(UNICODE_VERSION, "14.0.0")
        # PropList.txt 14.0.0 enumerates exactly 56 Soft_Dotted code points.
        self.assertEqual(len(_SOFT_DOTTED), 56)
        # Spot-check membership: U+0131 is Soft_Dotted, U+0249 is not.
        self.assertIn(IDOTLESS, _SOFT_DOTTED)
        self.assertNotIn("ɉ", _SOFT_DOTTED)

    def test_apply_transform_keeps_neutral_default(self) -> None:
        spec = TransformSpec(normalization="NFC", case="lower")
        # No language argument -> original locale-neutral behavior.
        self.assertEqual(apply_transform(I, spec), i_)
        # Explicit non-Turkic language also stays neutral.
        self.assertEqual(apply_transform(I, spec, language="en"), i_)
        # Opt-in tr/az uses the full-context mapping.
        self.assertEqual(apply_transform(I, spec, language="tr"), IDOTLESS)
        self.assertEqual(apply_transform(I, spec, language="az"), IDOTLESS)

    def test_traced_pipeline_order_and_codepoints(self) -> None:
        spec = TransformSpec(normalization="NFC", case="lower")
        text = unicodedata.normalize("NFD", IDOT)  # I + U+0307
        out, trace = apply_transform_traced(text, spec, language="tr")
        self.assertEqual(out, i_)
        self.assertEqual(trace.case_contract, "turkic_tr")
        stage_names = [stage.stage for stage in trace.stages]
        self.assertEqual(
            stage_names,
            [
                "invisible_remove",
                "width_fold",
                "normalize_NFC",
                "case_lower",
                "collapse_whitespace",
                "trim",
            ],
        )
        # NFC composes I+U+0307 into U+0130 before the case stage runs.
        normalize_stage = next(s for s in trace.stages if s.stage == "normalize_NFC")
        self.assertEqual(normalize_stage.output_codepoints, ("U+0130",))
        case_stage = next(s for s in trace.stages if s.stage == "case_lower")
        self.assertEqual(case_stage.output_codepoints, ("U+0069",))
        self.assertEqual(trace.final_codepoints, ("U+0069",))
        self.assertEqual(trace.raw_codepoints, ("U+0049", "U+0307"))

    def test_nfd_pipeline_converges_with_precomposed_input(self) -> None:
        spec_nfc = TransformSpec(normalization="NFC", case="lower")
        spec_nfd = TransformSpec(normalization="NFD", case="lower")
        self.assertEqual(
            apply_transform(IDOT, spec_nfc, language="tr"),
            apply_transform(I + DOT, spec_nfd, language="tr"),
        )

    def test_make_target_key_language_parameter(self) -> None:
        spec = TransformSpec(normalization="NFC", case="lower")
        self.assertEqual(
            make_target_key([I, IDOT], spec, language="tr"),
            IDOTLESS + UNIT_SEPARATOR + i_,
        )


class _EngineFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _scan(
        self,
        rows: list[dict[str, str]],
        *,
        keys: list[dict],
        filename: str = "data.jsonl",
        kind: str = "jsonl",
    ):
        path = self.root / filename
        if kind == "jsonl":
            path.write_text(
                "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
                encoding="utf-8",
            )
        else:
            import csv as _csv
            import io as _io

            buffer = _io.StringIO()
            writer = _csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
            path.write_text(buffer.getvalue(), encoding="utf-8")
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": kind,
                "path": filename,
                "record_id_field": "id",
            },
            keys=keys,
        )
        config = load_config(
            write_config(self.root / "config.json", config_data)
        )
        return scan(config, load_sources(config))

    def _results_by_id(self, result) -> dict[str, object]:
        return {item.record_id: item for item in result.key_results}

    def _codes(self, result) -> set[str]:
        return set(result.summary["findings_by_code"])


class LanguageAwareContractTests(_EngineFixture):
    """Acceptance: language_aware yields the two correct business classes."""

    POLICY = language_policy(contract="language_aware", tag_field="lang")

    def _rows(self) -> list[dict[str, str]]:
        return [
            {"id": "r1", "name": I, "lang": "tr"},
            {"id": "r2", "name": IDOTLESS, "lang": "tr"},
            {"id": "r3", "name": IDOT, "lang": "tr"},
            {"id": "r4", "name": i_, "lang": "tr"},
            {"id": "r5", "name": I + DOT, "lang": "tr"},
            {"id": "r6", "name": IDOT, "lang": "az"},
        ]

    def test_two_turkic_equivalence_classes(self) -> None:
        result = self._scan(
            self._rows(),
            keys=[
                language_key(
                    key_id="name_tr",
                    source_id="s1",
                    columns=["name"],
                    policy=self.POLICY,
                )
            ],
        )
        by_id = self._results_by_id(result)
        self.assertEqual(by_id["r1"].target_key, IDOTLESS)
        self.assertEqual(by_id["r2"].target_key, IDOTLESS)
        self.assertEqual(by_id["r3"].target_key, i_)
        self.assertEqual(by_id["r4"].target_key, i_)
        self.assertEqual(by_id["r5"].target_key, i_)
        # Azerbaijani shares the same tr/az SpecialCasing contract.
        self.assertEqual(by_id["r6"].target_key, i_)
        # Two real collisions within the two business classes.
        self.assertEqual(result.summary["collision_groups"], 2)
        reasons = {group.reason_code for group in result.collisions}
        self.assertEqual(reasons, {"NORMALIZATION_COLLISION"})
        # The dotted-i class mixes tr and az tags: that is expected, and the
        # cross-language flag records it without hiding the collision.
        dotted = next(
            group for group in result.collisions if group.target_key == i_
        )
        self.assertTrue(dotted.cross_language)
        self.assertEqual(dotted.languages, ["az", "tr"])
        dotless = next(
            group for group in result.collisions
            if group.target_key == IDOTLESS
        )
        self.assertFalse(dotless.cross_language)

    def test_utf8_bytes_are_recomputed_per_language_semantics(self) -> None:
        result = self._scan(
            self._rows(),
            keys=[
                language_key(
                    key_id="name_tr",
                    source_id="s1",
                    columns=["name"],
                    policy=self.POLICY,
                )
            ],
        )
        by_id = self._results_by_id(result)
        self.assertEqual(
            by_id["r1"].key_bytes, len(IDOTLESS.encode("utf-8"))
        )
        self.assertEqual(by_id["r1"].key_bytes, 2)  # U+0131 -> 0xC4 0xB1
        self.assertEqual(by_id["r3"].key_bytes, 1)  # ASCII i
        self.assertEqual(by_id["r1"].key_sha256 is not None, True)

    def test_traces_record_raw_and_transformed_codepoints(self) -> None:
        result = self._scan(
            self._rows(),
            keys=[
                language_key(
                    key_id="name_tr",
                    source_id="s1",
                    columns=["name"],
                    policy=self.POLICY,
                )
            ],
        )
        by_id = self._results_by_id(result)
        trace = by_id["r5"].traces[0]
        self.assertIsInstance(trace, TransformTrace)
        self.assertEqual(trace.raw_codepoints, ("U+0049", "U+0307"))
        self.assertEqual(trace.final_codepoints, ("U+0069",))
        self.assertEqual(trace.language, "tr")
        self.assertEqual(trace.case_contract, "turkic_tr")
        # Every stage is present and ordered.
        self.assertEqual(len(trace.stages), 6)

    def test_casefold_contract_and_upper_contract(self) -> None:
        for case, expected_i, expected_idot in (
            ("casefold", IDOTLESS, i_),
            ("upper", I, IDOT),
        ):
            result = self._scan(
                [
                    {"id": "a", "name": I, "lang": "tr"},
                    {"id": "b", "name": IDOT, "lang": "tr"},
                ],
                keys=[
                    language_key(
                        key_id="k",
                        source_id="s1",
                        columns=["name"],
                        policy=self.POLICY,
                        case=case,
                    )
                ],
            )
            by_id = self._results_by_id(result)
            self.assertEqual(by_id["a"].target_key, expected_i, case)
            self.assertEqual(by_id["b"].target_key, expected_idot, case)
            self.assertEqual(by_id["a"].case_contract, "turkic_tr")

    def test_english_records_use_neutral_contract_under_language_aware(self) -> None:
        result = self._scan(
            [
                {"id": "e1", "name": "abc", "lang": "en"},
                {"id": "e2", "name": "xyz", "lang": "en"},
            ],
            keys=[
                language_key(
                    key_id="name_k",
                    source_id="s1",
                    columns=["name"],
                    policy=self.POLICY,
                )
            ],
        )
        by_id = self._results_by_id(result)
        self.assertEqual(by_id["e1"].target_key, "abc")  # neutral lower
        self.assertEqual(by_id["e1"].case_contract, "neutral")
        self.assertEqual(by_id["e1"].language_tag, "en")
        self.assertNotIn("LANGUAGE_TAG_UNSUPPORTED", self._codes(result))
        self.assertEqual(by_id["e1"].language_status, "unsupported")

    def test_cross_language_collision_remains_visible(self) -> None:
        # English I -> neutral "i"; tr İ -> Turkic "i". Same shared target key.
        result = self._scan(
            [
                {"id": "en1", "name": I, "lang": "en"},
                {"id": "tr1", "name": IDOT, "lang": "tr"},
            ],
            keys=[
                language_key(
                    key_id="shared_idx",
                    source_id="s1",
                    columns=["name"],
                    policy=self.POLICY,
                )
            ],
        )
        self.assertEqual(len(result.collisions), 1)
        group = result.collisions[0]
        self.assertTrue(group.cross_language)
        self.assertEqual(group.languages, ["en", "tr"])
        codes = self._codes(result)
        self.assertIn("CROSS_LANGUAGE_COLLISION", codes)
        self.assertIn("NORMALIZATION_COLLISION", codes)
        cross = next(f for f in result.findings if f.code == "CROSS_LANGUAGE_COLLISION")
        self.assertEqual(cross.details["languages"], ["en", "tr"])

    def test_missing_invalid_and_unsupported_tags_never_guess(self) -> None:
        result = self._scan(
            [
                {"id": "m1", "name": I, "lang": ""},          # missing
                {"id": "m2", "name": I},                        # field absent
                {"id": "b1", "name": I, "lang": "not-a-tag!"},  # invalid
                {"id": "u1", "name": I, "lang": "fr"},         # unsupported + sensitive
                {"id": "u2", "name": "abc", "lang": "fr"},     # unsupported, harmless
            ],
            keys=[
                language_key(
                    key_id="name_k",
                    source_id="s1",
                    columns=["name"],
                    policy=self.POLICY,
                )
            ],
        )
        codes = self._codes(result)
        self.assertIn("LANGUAGE_TAG_MISSING", codes)
        self.assertIn("LANGUAGE_TAG_INVALID", codes)
        self.assertIn("LANGUAGE_TAG_UNSUPPORTED", codes)
        by_id = self._results_by_id(result)
        # Neutral mapping is still emitted for audit, but nothing is guessed.
        self.assertEqual(by_id["m1"].target_key, i_)
        self.assertEqual(by_id["m1"].language_status, "missing")
        self.assertEqual(by_id["b1"].language_status, "invalid")
        self.assertEqual(by_id["u1"].language_status, "unsupported")
        self.assertEqual(by_id["u2"].language_status, "unsupported")
        self.assertEqual(by_id["u1"].case_contract, "neutral")
        # Harmless unsupported-language row carries no blocking defect.
        u2_defects = {d.code for d in by_id["u2"].defects}
        self.assertNotIn("LANGUAGE_TAG_UNSUPPORTED", u2_defects)
        # The preflight summary records every status: 2 missing + 1 invalid +
        # 2 unsupported are blocked; only the harmless French row is migratable.
        bucket = result.summary["language_preflight"]["rules"]["name_k"]
        self.assertEqual(bucket["blocked_by_language"], 4)
        self.assertEqual(bucket["migratable"], 1)
        self.assertEqual(bucket["by_status"]["missing"], 2)
        self.assertEqual(bucket["by_status"]["invalid"], 1)
        self.assertEqual(bucket["by_status"]["unsupported"], 2)

    def test_bcp47_subtags_are_normalized(self) -> None:
        result = self._scan(
            [
                {"id": "z1", "name": I, "lang": "tr-TR"},
                {"id": "z2", "name": I, "lang": "az-Latn-AZ"},
                {"id": "z3", "name": I, "lang": "TR"},
            ],
            keys=[
                language_key(
                    key_id="name_k",
                    source_id="s1",
                    columns=["name"],
                    policy=self.POLICY,
                )
            ],
        )
        by_id = self._results_by_id(result)
        for record_id in ("z1", "z2", "z3"):
            self.assertIn(by_id[record_id].language_tag, TURKIC_LANGUAGES)
            self.assertEqual(by_id[record_id].target_key, IDOTLESS)
            self.assertEqual(by_id[record_id].language_status, "resolved")

    def test_unified_default_language_source(self) -> None:
        policy = language_policy(
            contract="language_aware", default_language="tr"
        )
        result = self._scan(
            [
                {"id": "d1", "name": I},
                {"id": "d2", "name": IDOT},
            ],
            keys=[
                language_key(
                    key_id="name_k",
                    source_id="s1",
                    columns=["name"],
                    policy=policy,
                )
            ],
        )
        by_id = self._results_by_id(result)
        self.assertEqual(by_id["d1"].language_status, "declared")
        self.assertEqual(by_id["d1"].language_tag, "tr")
        self.assertEqual(by_id["d1"].target_key, IDOTLESS)
        self.assertEqual(by_id["d2"].target_key, i_)


class NeutralOnlyContractTests(_EngineFixture):
    """Acceptance: neutral_only blocks Turkic special-case keys."""

    POLICY = language_policy(contract="neutral_only", tag_field="lang")

    def test_turkic_sensitive_records_are_blocked(self) -> None:
        result = self._scan(
            [
                {"id": "n1", "name": I, "lang": "tr"},
                {"id": "n2", "name": IDOT, "lang": "az"},
                {"id": "n3", "name": "abc", "lang": "tr"},
                {"id": "n4", "name": I, "lang": "en"},
            ],
            keys=[
                language_key(
                    key_id="name_n",
                    source_id="s1",
                    columns=["name"],
                    policy=self.POLICY,
                )
            ],
        )
        codes = self._codes(result)
        self.assertIn("TURKIC_CASE_GOVERNANCE_REQUIRED", codes)
        governance = [
            f for f in result.findings
            if f.code == "TURKIC_CASE_GOVERNANCE_REQUIRED"
        ]
        self.assertEqual(len(governance), 2)  # n1 and n2 only
        by_id = self._results_by_id(result)
        # Neutral output is retained for audit; contract stays neutral.
        self.assertEqual(by_id["n1"].target_key, i_)
        self.assertEqual(by_id["n1"].case_contract, "neutral")
        # The harmless tr row is not Turkic-blocked; the English row with an
        # I-family codepoint is unsupported-and-sensitive, so it is blocked by
        # the language gate rather than silently mapped.
        n3_defects = {d.code for d in by_id["n3"].defects}
        n4_defects = {d.code for d in by_id["n4"].defects}
        self.assertNotIn("TURKIC_CASE_GOVERNANCE_REQUIRED", n3_defects)
        self.assertNotIn("TURKIC_CASE_GOVERNANCE_REQUIRED", n4_defects)
        self.assertIn("LANGUAGE_TAG_UNSUPPORTED", n4_defects)
        bucket = result.summary["language_preflight"]["rules"]["name_n"]
        self.assertEqual(bucket["blocked_by_language"], 3)
        self.assertEqual(bucket["migratable"], 1)

    def test_two_contracts_diverge_on_migratable_count_and_bytes(self) -> None:
        # Distinct prefixes keep the target keys unique so the language-aware
        # route has no collisions; only the language gate can block.
        rows = [
            {"id": "a", "name": "a" + I, "lang": "tr"},
            {"id": "b", "name": "b" + IDOTLESS, "lang": "tr"},
            {"id": "c", "name": "c" + IDOT, "lang": "tr"},
            {"id": "d", "name": "d" + i_, "lang": "tr"},
        ]
        neutral = self._scan(
            rows,
            keys=[
                language_key(
                    key_id="k",
                    source_id="s1",
                    columns=["name"],
                    policy=language_policy(contract="neutral_only", tag_field="lang"),
                )
            ],
        )
        aware = self._scan(
            rows,
            keys=[
                language_key(
                    key_id="k",
                    source_id="s1",
                    columns=["name"],
                    policy=language_policy(
                        contract="language_aware", tag_field="lang"
                    ),
                )
            ],
        )
        nb = neutral.summary["language_preflight"]["rules"]["k"]
        ab = aware.summary["language_preflight"]["rules"]["k"]
        self.assertEqual(nb["migratable"], 0)
        self.assertEqual(nb["blocked_by_language"], 4)
        self.assertEqual(ab["migratable"], 4)
        # Target key bytes differ: neutral collapses I -> 1-byte "i", the
        # Turkic contract keeps I -> 2-byte U+0131.
        neutral_bytes = {
            item.record_id: item.key_bytes for item in neutral.key_results
        }
        aware_bytes = {
            item.record_id: item.key_bytes for item in aware.key_results
        }
        # "a" + neutral lower(I) -> "ai" (2 bytes); the Turkic contract yields
        # "a" + U+0131 (3 bytes) because dotless i encodes to two UTF-8 bytes.
        self.assertEqual(neutral_bytes["a"], 2)
        self.assertEqual(aware_bytes["a"], 3)
        # And the plan verdicts differ because neutral_only blocks the run
        # (high-severity governance findings), while language_aware passes.
        self.assertEqual(neutral.verdict, "blocked")
        self.assertEqual(aware.verdict, "pass")
        self.assertFalse(neutral.plan["gate"]["passes"])
        self.assertTrue(aware.plan["gate"]["passes"])


class NfcOrderingAndCsvTests(_EngineFixture):
    def test_composite_key_applies_turkic_mapping_per_component(self) -> None:
        policy = language_policy(contract="language_aware", tag_field="lang")
        result = self._scan(
            [{"id": "k1", "city": I, "name": IDOT, "lang": "tr"}],
            keys=[
                language_key(
                    key_id="comp",
                    source_id="s1",
                    columns=["city", "name"],
                    policy=policy,
                )
            ],
        )
        item = result.key_results[0]
        self.assertEqual(item.target_key, IDOTLESS + UNIT_SEPARATOR + i_)
        self.assertEqual(len(item.traces), 2)
        self.assertEqual([t.component_index for t in item.traces], [0, 1])
        self.assertTrue(all(t.case_contract == "turkic_tr" for t in item.traces))

    def test_upper_contract_engine_trace(self) -> None:
        policy = language_policy(contract="language_aware", tag_field="lang")
        result = self._scan(
            [{"id": "u1", "name": i_, "lang": "tr"}],
            keys=[
                language_key(
                    key_id="up",
                    source_id="s1",
                    columns=["name"],
                    policy=policy,
                    case="upper",
                )
            ],
        )
        item = result.key_results[0]
        self.assertEqual(item.target_key, IDOT)
        case_stage = next(
            s for s in item.traces[0].stages if s.stage == "case_upper"
        )
        self.assertEqual(case_stage.output_codepoints, ("U+0130",))

    def test_nfc_then_case_order_with_decomposed_input(self) -> None:
        policy = language_policy(contract="language_aware", tag_field="lang")
        result = self._scan(
            [
                {"id": "s1", "name": I + DOT, "lang": "tr"},
                {"id": "s2", "name": IDOT, "lang": "tr"},
            ],
            keys=[
                language_key(
                    key_id="k",
                    source_id="s1",
                    columns=["name"],
                    policy=policy,
                    normalization="NFC",
                )
            ],
        )
        # Both converge to "i" and collide as one genuine business class.
        self.assertEqual(len(result.collisions), 1)
        for item in result.key_results:
            self.assertEqual(item.target_key, i_)

    def test_csv_source_with_language_column(self) -> None:
        policy = language_policy(contract="language_aware", tag_field="lang")
        result = self._scan(
            [
                {"id": "c1", "name": I, "lang": "tr"},
                {"id": "c2", "name": IDOTLESS, "lang": "tr"},
            ],
            keys=[
                language_key(
                    key_id="k",
                    source_id="s1",
                    columns=["name"],
                    policy=policy,
                )
            ],
            filename="data.csv",
            kind="csv",
        )
        by_id = self._results_by_id(result)
        self.assertEqual(by_id["c1"].target_key, IDOTLESS)
        self.assertEqual(by_id["c2"].target_key, IDOTLESS)
        self.assertEqual(len(result.collisions), 1)
        self.assertFalse(result.collisions[0].cross_language)


class ConfigValidationTests(_EngineFixture):
    def _expect_config_error(self, config_data: dict, pattern: str) -> None:
        path = write_config(self.root / "config.json", config_data)
        from charorder.errors import ConfigError

        with self.assertRaisesRegex(ConfigError, pattern):
            load_config(path)

    def _base(self, policy: dict) -> dict:
        return minimal_config(
            source={
                "id": "s1",
                "type": "jsonl",
                "path": "data.jsonl",
                "record_id_field": "id",
            },
            keys=[
                language_key(
                    key_id="k",
                    source_id="s1",
                    columns=["name"],
                    policy=policy,
                )
            ],
        )

    def test_unknown_contract_rejected(self) -> None:
        (self.root / "data.jsonl").write_text(
            json.dumps({"id": "1", "name": I, "lang": "tr"}) + "\n",
            encoding="utf-8",
        )
        self._expect_config_error(
            self._base(language_policy(contract="icu", tag_field="lang")),
            "contract 必须是",
        )

    def test_tag_sources_are_mutually_exclusive(self) -> None:
        (self.root / "data.jsonl").write_text(
            json.dumps({"id": "1", "name": I}) + "\n", encoding="utf-8"
        )
        policy = {
            "contract": "language_aware",
            "tag_field": "lang",
            "default_language": "tr",
        }
        self._expect_config_error(self._base(policy), "互斥")

    def test_one_tag_source_is_required(self) -> None:
        (self.root / "data.jsonl").write_text(
            json.dumps({"id": "1", "name": I}) + "\n", encoding="utf-8"
        )
        self._expect_config_error(
            self._base({"contract": "language_aware"}), "tag_field"
        )

    def test_unsupported_language_in_config_rejected(self) -> None:
        (self.root / "data.jsonl").write_text(
            json.dumps({"id": "1", "name": I}) + "\n", encoding="utf-8"
        )
        self._expect_config_error(
            self._base(
                language_policy(
                    contract="language_aware",
                    default_language="fr",
                    supported_languages=["tr", "az", "fr"],
                )
            ),
            "仅支持 tr / az",
        )

    def test_policy_requires_a_case_mapping(self) -> None:
        (self.root / "data.jsonl").write_text(
            json.dumps({"id": "1", "name": I, "lang": "tr"}) + "\n",
            encoding="utf-8",
        )
        config_data = self._base(
            language_policy(contract="language_aware", tag_field="lang")
        )
        config_data["keys"][0]["transform"]["case"] = "none"
        self._expect_config_error(config_data, "transform.case")

    def test_unknown_policy_field_rejected(self) -> None:
        (self.root / "data.jsonl").write_text(
            json.dumps({"id": "1", "name": I, "lang": "tr"}) + "\n",
            encoding="utf-8",
        )
        policy = language_policy(contract="neutral_only", tag_field="lang")
        policy["locale"] = "tr_TR.UTF-8"
        self._expect_config_error(self._base(policy), "未知字段")

    def test_invalid_default_language_rejected(self) -> None:
        (self.root / "data.jsonl").write_text(
            json.dumps({"id": "1", "name": I}) + "\n", encoding="utf-8"
        )
        self._expect_config_error(
            self._base(
                language_policy(contract="language_aware", default_language="turkish")
            ),
            "不是合法语言标签",
        )


class LegacyCompatibilityTests(_EngineFixture):
    """Old configs without language_policy keep identical behavior."""

    def test_legacy_config_has_no_language_semantics(self) -> None:
        from tests.support import ci_key

        result = self._scan(
            [
                {"id": "1", "name": "Straße"},
                {"id": "2", "name": "STRASSE"},
            ],
            keys=[ci_key(key_id="legacy", source_id="s1", columns=["name"])],
        )
        for item in result.key_results:
            self.assertEqual(item.language_status, "not_configured")
            self.assertIsNone(item.language_tag)
            self.assertEqual(item.case_contract, "neutral")
            self.assertIsNotNone(item.traces)
        self.assertEqual(result.summary["language_preflight"]["rules"], {})
        self.assertNotIn("language_contracts", result.plan)
        # Locale-neutral casefold still collapses the two forms.
        self.assertEqual(len(result.collisions), 1)

class ArtifactIntegrationLanguageTests(_EngineFixture):
    def test_full_run_artifacts_ledger_and_verify(self) -> None:
        rows = [
            {"id": "t1", "name": I, "lang": "tr"},
            {"id": "t2", "name": IDOT, "lang": "tr"},
            {"id": "e1", "name": I, "lang": "en"},
            {"id": "x1", "name": I, "lang": ""},
        ]
        path = self.root / "data.jsonl"
        path.write_text(
            "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
            encoding="utf-8",
        )
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": "jsonl",
                "path": "data.jsonl",
                "record_id_field": "id",
            },
            keys=[
                language_key(
                    key_id="name_k",
                    source_id="s1",
                    columns=["name"],
                    policy=language_policy(
                        contract="language_aware", tag_field="lang"
                    ),
                )
            ],
        )
        config = load_config(write_config(self.root / "config.json", config_data))
        result, manifest, output = execute(config, self.root / "run")

        # verify_run still passes with the v2 ledger schema.
        report = verify_run(output)
        self.assertTrue(report["html_self_contained"])

        # keys.jsonl carries language evidence and traces.
        keys_doc = [
            json.loads(line)
            for line in (output / "keys.jsonl").read_text("utf-8").splitlines()
        ]
        by_id = {row["record_id"]: row for row in keys_doc}
        self.assertEqual(by_id["t1"]["language_tag"], "tr")
        self.assertEqual(by_id["t1"]["case_contract"], "turkic_tr")
        self.assertEqual(by_id["t1"]["target_key"], IDOTLESS)
        self.assertTrue(by_id["t1"]["transform_traces"])
        self.assertEqual(
            by_id["t1"]["transform_traces"][0]["raw_codepoints"], ["U+0049"]
        )

        # Ledger: new columns, trace table, cross-language collision flags.
        connection = sqlite3.connect(
            (output / "ledger.sqlite").as_uri() + "?mode=ro", uri=True
        )
        try:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0], 2
            )
            row = connection.execute(
                "SELECT language_tag, language_status, case_contract, key_bytes "
                "FROM key_results WHERE record_id = 't1'"
            ).fetchone()
            self.assertEqual(row, ("tr", "resolved", "turkic_tr", 2))
            trace_count = connection.execute(
                "SELECT COUNT(*) FROM key_transform_traces"
            ).fetchone()[0]
            self.assertEqual(trace_count, 4)
            # t2 (tr İ -> i), e1 (en I -> i) and x1 (missing tag, neutral
            # I -> i) all share the target key: the cross-language flag and
            # the unknown tag are both visible rather than masked.
            collision = connection.execute(
                "SELECT languages_json, cross_language FROM collisions"
            ).fetchone()
            self.assertEqual(json.loads(collision[0]), ["en", "tr", "unknown"])
            self.assertEqual(collision[1], 1)
        finally:
            connection.close()

        # Plan and manifest stay internally consistent.
        plan = json.loads((output / "plan.json").read_text("utf-8"))
        self.assertIn("language_contracts", plan)
        bucket = plan["language_contracts"]["rules"]["name_k"]
        self.assertEqual(bucket["records"], 4)
        self.assertEqual(bucket["turkic_mapped"], 2)
        self.assertEqual(
            manifest["summary"]["language_preflight"]["rules"]["name_k"]["records"],
            4,
        )
        # HTML/MD surface the cross-language flag and the language section.
        html = (output / "report.html").read_text("utf-8")
        self.assertIn("语言身份键预检", html)
        self.assertIn("跨语言碰撞", html)
        md = (output / "report.md").read_text("utf-8")
        self.assertIn("语言身份键预检", md)

    def test_deterministic_runs_byte_identical(self) -> None:
        rows = [{"id": "t1", "name": IDOT, "lang": "az"}]
        path = self.root / "data.jsonl"
        path.write_text(
            "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
            encoding="utf-8",
        )
        config_data = minimal_config(
            source={
                "id": "s1",
                "type": "jsonl",
                "path": "data.jsonl",
                "record_id_field": "id",
            },
            keys=[
                language_key(
                    key_id="name_k",
                    source_id="s1",
                    columns=["name"],
                    policy=language_policy(
                        contract="language_aware", tag_field="lang"
                    ),
                )
            ],
        )
        config = load_config(write_config(self.root / "config.json", config_data))
        _, _, out1 = execute(config, self.root / "run-a")
        _, _, out2 = execute(config, self.root / "run-b")
        for name in ("plan.json", "keys.jsonl", "findings.json"):
            self.assertEqual(
                (out1 / name).read_bytes(), (out2 / name).read_bytes(), name
            )


if __name__ == "__main__":
    unittest.main()
