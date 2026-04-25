"""Unit tests for the docx → markdown lesson extractor.

Builds tiny fake docx-like trees in-memory so we don't need the real
.docx files. The full end-to-end extractor against the actual docx is
exercised by the integration test.
"""

from __future__ import annotations

from twisted.training import extractor as ex


def _section(level: int, title: str, body: str | None = None,
             children: list[ex.DocxSection] | None = None) -> ex.DocxSection:
    s = ex.DocxSection(level=level, title=title,
                       body_paragraphs=[body] if body else [],
                       children=list(children or []))
    for c in s.children:
        c.parent = s
    return s


class TestSimilarity:
    def test_token_overlap_dominates(self) -> None:
        # Identical token set → very high score
        assert ex._similarity("Certificate Transparency Logs",
                               "Transparency Logs Certificate") > 0.85

    def test_partial_overlap(self) -> None:
        score = ex._similarity("DNS Record Enumeration",
                                "DNS Records and Their Significance")
        # Some overlap on "dns" + "record(s)" — should be in the
        # moderate band, well below an exact match.
        assert 0.2 < score < 0.85

    def test_disjoint_tokens_low_score(self) -> None:
        assert ex._similarity("nmap port scan", "html report builder") < 0.2

    def test_stopwords_dropped(self) -> None:
        # "stage" and "phase" shouldn't influence matching — tokens
        # collapse to {reconnaissance} vs {1, reconnaissance}
        score = ex._similarity("Stage 1 Reconnaissance", "Reconnaissance")
        assert score >= 0.5


class _FakeStep:
    def __init__(self, sid: str, name: str) -> None:
        self.id = sid
        self.name = name


class TestBestMatch:
    def test_returns_strongest_candidate(self) -> None:
        cands = [
            _section(2, "Procedure A: HTTP Header Analysis"),
            _section(2, "Procedure B: TLS Certificate Inspection"),
            _section(2, "Procedure C: WHOIS Lookup"),
        ]
        step = _FakeStep("bb.stage3.headers_audit", "HTTP Header Analysis")
        match, score = ex.best_match(step, cands, min_score=0.0)
        assert match.title.startswith("Procedure A")
        assert score > 0.5

    def test_below_threshold_returns_none(self) -> None:
        cands = [_section(2, "Completely Unrelated Section")]
        step = _FakeStep("bb.stage3.tls_audit", "TLS Certificate Inspection")
        match, score = ex.best_match(step, cands, min_score=0.5)
        assert match is None
        assert score < 0.5

    def test_override_takes_effect(self) -> None:
        cands = [
            _section(2, "Pre-Engagement Setup"),
            _section(2, "Stress Testing"),
        ]
        step = _FakeStep("wp_stress.phase1.baseline_ab",
                          "Baseline performance with Apache Bench")
        # Without an override, we'd match poorly; with the override
        # in STEP_NAME_OVERRIDES we map to "Pre-Engagement Setup".
        assert ex.STEP_NAME_OVERRIDES.get(step.id) == "Pre-Engagement Setup"
        match, score = ex.best_match(step, cands, min_score=0.0)
        assert match.title == "Pre-Engagement Setup"
        assert score > 0.5


class TestSectionToLessonBody:
    def test_h3_children_canonicalise(self) -> None:
        parent = _section(
            2, "Procedure A",
            children=[
                _section(3, "What We Are Doing", "doing things"),
                _section(3, "Step-by-Step Execution", "do step 1"),
                _section(3, "Why This Matters", "because reasons"),
            ],
        )
        body = ex.section_to_lesson_body(parent)
        assert body["what"] == "doing things"
        assert body["how"] == "do step 1"
        assert body["why"] == "because reasons"

    def test_recursive_h2_children_under_h1(self) -> None:
        h1 = _section(
            1, "1. Pre-Engagement Setup",
            children=[
                _section(2, "1.1 Why We Do This", "to set baseline"),
                _section(2, "1.3 Steps", "step list"),
                _section(2, "1.4 What to Collect", "logs and screenshots"),
            ],
        )
        body = ex.section_to_lesson_body(h1)
        assert body["why"].startswith("to set baseline")
        assert body["how"].startswith("step list")
        assert body["what_to_collect"].startswith("logs")

    def test_lead_body_becomes_what(self) -> None:
        section = _section(2, "Some Procedure", body="leading prose here")
        body = ex.section_to_lesson_body(section)
        assert body["what"] == "leading prose here"

    def test_free_form_why_prefix(self) -> None:
        parent = _section(
            2, "Procedure",
            children=[
                _section(3, "Why Clients Have Forgotten Subdomains",
                          "they forget"),
            ],
        )
        body = ex.section_to_lesson_body(parent)
        assert "they forget" in body["why"]


class TestRenderMarkdown:
    def test_includes_frontmatter_and_canonical_sections(self) -> None:
        lesson = ex.StepLesson(
            step_id="bb.stage1.crtsh", procedure="bb", stage="stage1",
            title="Certificate Transparency Log Harvesting",
            sections={"what": "ct logs", "why": "find subdomains",
                      "how": "search crt.sh"},
            matched=True, match_score=0.9,
        )
        md = ex.render_markdown(lesson)
        assert md.startswith("---\n")
        assert "step_id: bb.stage1.crtsh" in md
        assert "procedure: bb" in md
        assert "stage: stage1" in md
        assert "## What We Are Doing" in md
        assert "## Why" in md
        assert "## How" in md
        assert "ct logs" in md
        # Title with no special chars left unquoted
        assert "title: Certificate Transparency Log Harvesting\n" in md

    def test_placeholder_marker_when_unmatched(self) -> None:
        lesson = ex.StepLesson(
            step_id="bb.stage5.unknown", procedure="bb", stage="stage5",
            title="X", sections={}, matched=False, match_score=0.05,
        )
        md = ex.render_markdown(lesson)
        assert "_This lesson is a placeholder" in md

    def test_yaml_scalar_quotes_special_chars(self) -> None:
        lesson = ex.StepLesson(
            step_id="x.y.z", procedure="x", stage="y",
            title="Tools: Used in This Phase",  # contains ':'
            sections={"what": "x"}, matched=True, match_score=0.9,
        )
        md = ex.render_markdown(lesson)
        assert 'title: "Tools: Used in This Phase"' in md
