from __future__ import annotations

import unittest

from charorder.models import TransformSpec
from charorder.transforms import (
    UNIT_SEPARATOR,
    analyze_text,
    apply_transform,
    escaped_text,
    fold_width,
    format_raw_values,
    make_target_key,
    sanitize_text,
    sha256_text,
    utf8_bytes,
)


class WidthFoldTests(unittest.TestCase):
    def test_fullwidth_ascii_and_ideographic_space_fold(self) -> None:
        self.assertEqual(fold_width("ＡＢＣ　１２３"), "ABC 123")

    def test_halfwidth_katakana_folds_and_composes(self) -> None:
        self.assertEqual(fold_width("ｶﾀｶﾅ ﾏｸﾞ"), "カタカナ マグ")

    def test_wide_cjk_is_not_folded(self) -> None:
        self.assertEqual(fold_width("蓝海科技"), "蓝海科技")

    def test_compatibility_character_is_not_width_folded(self) -> None:
        # NFKC would turn these into "1" and "fi"; width folding must not.
        self.assertEqual(fold_width("① ﬁ"), "① ﬁ")


class TransformPipelineTests(unittest.TestCase):
    def test_composed_and_decomposed_forms_converge(self) -> None:
        spec = TransformSpec(normalization="NFC", case="casefold", width_fold=True)
        self.assertEqual(apply_transform("Café", spec), "café")
        self.assertEqual(apply_transform("CAFÉ", spec), "café")

    def test_casefold_expands_german_sharp_s(self) -> None:
        self.assertEqual(
            apply_transform("Straße", TransformSpec(case="casefold")),
            "strasse",
        )

    def test_upper_and_lower_are_locale_independent(self) -> None:
        self.assertEqual(apply_transform("i", TransformSpec(case="upper")), "I")
        self.assertEqual(apply_transform("İ", TransformSpec(case="lower")), "i̇")

    def test_invisible_policy_removes_format_characters(self) -> None:
        spec = TransformSpec(invisible="remove")
        self.assertEqual(apply_transform("Li​Lei", spec), "LiLei")
        self.assertEqual(apply_transform("a­b", spec), "ab")
        # Bidi controls are Cf and are also removed by the declared policy.
        self.assertEqual(apply_transform("safe‮gnp", spec), "safegnp")

    def test_invisible_policy_keep_preserves_format_characters(self) -> None:
        self.assertEqual(
            apply_transform("a​b", TransformSpec(invisible="keep")),
            "a​b",
        )

    def test_whitespace_collapse_and_trim(self) -> None:
        spec = TransformSpec(
            collapse_whitespace=True,
            trim=True,
            normalization="none",
        )
        self.assertEqual(apply_transform("  a 　\tb  ", spec), "a b")

    def test_trim_without_collapse_keeps_internal_whitespace(self) -> None:
        spec = TransformSpec(
            collapse_whitespace=False,
            trim=True,
            normalization="none",
        )
        self.assertEqual(apply_transform("  a  b  ", spec), "a  b")

    def test_fixed_pipeline_order(self) -> None:
        spec = TransformSpec(
            normalization="NFC",
            case="casefold",
            width_fold=True,
            trim=True,
            collapse_whitespace=True,
            invisible="remove",
        )
        self.assertEqual(apply_transform("　Ａ​Ｂ　", spec), "ab")

    def test_composite_key_uses_unit_separator(self) -> None:
        spec = TransformSpec(normalization="NFC", case="casefold")
        self.assertEqual(
            make_target_key(["ACME", "Tokyo"], spec),
            "acme" + UNIT_SEPARATOR + "tokyo",
        )


class AnalysisTests(unittest.TestCase):
    def _codes(self, value: str) -> set[str]:
        return {issue.code for issue in analyze_text(value)}

    def test_zwsp_and_soft_hyphen_are_invisible(self) -> None:
        issues = analyze_text("Li​­Lei")
        invisible = [issue for issue in issues if issue.code == "INVISIBLE_CHARACTER"]
        self.assertEqual(len(invisible), 1)
        self.assertEqual(invisible[0].details["count"], 2)

    def test_bidi_control_is_classified_separately(self) -> None:
        codes = self._codes("safe‮gnp")
        self.assertIn("BIDI_CONTROL", codes)
        self.assertNotIn("INVISIBLE_CHARACTER", codes)

    def test_control_character_detected_but_whitespace_is_not_control(self) -> None:
        self.assertIn("CONTROL_CHARACTER", self._codes("bell\u0007"))
        self.assertNotIn("CONTROL_CHARACTER", self._codes("line\tbreak\nnext"))

    def test_replacement_and_mojibake_are_flagged(self) -> None:
        codes = self._codes("MÃ¼ller �")
        self.assertIn("REPLACEMENT_CHARACTER", codes)
        self.assertIn("MOJIBAKE_SUSPECT", codes)

    def test_surrogate_is_flagged(self) -> None:
        self.assertIn("SURROGATE_CHARACTER", self._codes("a\ud800b"))

    def test_abnormal_whitespace_reasons(self) -> None:
        issues = analyze_text("  a  b  ")
        issue = next(item for item in issues if item.code == "ABNORMAL_WHITESPACE")
        reasons = issue.details["issues"]
        self.assertIn("首尾空白", reasons)
        self.assertIn("连续空白", reasons)
        self.assertIn("2 个非普通空格空白", reasons)

    def test_whitespace_only_text(self) -> None:
        issues = analyze_text("　\t ")
        issue = next(item for item in issues if item.code == "ABNORMAL_WHITESPACE")
        self.assertIn("全空白", issue.details["issues"])

    def test_clean_text_has_no_issues(self) -> None:
        self.assertEqual(analyze_text("Plain ASCII 123"), [])


class DisplayAndEncodingTests(unittest.TestCase):
    def test_escaped_text_is_unambiguous(self) -> None:
        self.assertEqual(escaped_text("a​b\n"), "'a\\u200bb\\n'")
        self.assertEqual(escaped_text("it's"), "'it\\'s'")

    def test_raw_values_format(self) -> None:
        self.assertEqual(format_raw_values(("a",)), "'a'")
        self.assertEqual(
            format_raw_values(("a", None)),
            "['a', ∅]",
        )

    def test_utf8_length_counts_bytes_not_characters(self) -> None:
        self.assertEqual(len("蓝海"), 2)
        self.assertEqual(len(utf8_bytes("蓝海")), 6)
        self.assertEqual(utf8_bytes("a\ud800").decode("utf-8"), "a�")

    def test_hash_is_content_derived(self) -> None:
        self.assertEqual(sha256_text("abc"), sha256_text("abc"))
        self.assertNotEqual(sha256_text("abc"), sha256_text("abd"))
        self.assertEqual(len(sha256_text("abc")), 64)

    def test_sanitize_replaces_lone_surrogate(self) -> None:
        self.assertEqual(sanitize_text("x\ud800y"), "x�y")


if __name__ == "__main__":
    unittest.main()
