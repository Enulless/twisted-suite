"""Unit tests for the quiz loader, schema validation, and grader."""

from __future__ import annotations

from pathlib import Path

import pytest

from twisted.training.quizzes import (
    QuizLoadError,
    QuizNotFound,
    QuizRepo,
    grade,
    parse_quiz,
)

SAMPLE_YAML = """
id: bb.stage1.crtsh.quiz
step_id: bb.stage1.crtsh
title: CT Logs
pass_threshold: 0.75
questions:
  - id: q1
    type: multiple_choice
    prompt: What does CT do?
    choices:
      a: encrypts traffic
      b: logs every issued cert publicly
      c: replaces DNS
    answer: b
    explain: CT logs are append-only public records.
  - id: q2
    type: short_answer
    prompt: What wildcard char does crt.sh accept?
    answer: "%"
    accept:
      - "%."
    case_sensitive: false
"""


class TestParseQuiz:
    def test_round_trip(self) -> None:
        q = parse_quiz(SAMPLE_YAML)
        assert q.id == "bb.stage1.crtsh.quiz"
        assert q.step_id == "bb.stage1.crtsh"
        assert q.title == "CT Logs"
        assert q.pass_threshold == 0.75
        assert len(q.questions) == 2
        assert q.questions[0].type == "multiple_choice"
        assert q.questions[0].answer == "b"
        assert q.questions[0].choices["b"] == "logs every issued cert publicly"
        assert q.questions[1].type == "short_answer"
        assert q.questions[1].answer == "%"
        assert q.questions[1].accept == ["%."]

    def test_missing_id_raises(self) -> None:
        with pytest.raises(QuizLoadError):
            parse_quiz("step_id: x\nquestions:\n  - id: q\n    prompt: p\n    answer: a")

    def test_invalid_question_type_raises(self) -> None:
        with pytest.raises(QuizLoadError):
            parse_quiz("""
id: x
step_id: y
questions:
  - id: q
    type: drag_and_drop
    prompt: p
    answer: a
""")

    def test_mc_answer_not_in_choices_raises(self) -> None:
        with pytest.raises(QuizLoadError) as exc:
            parse_quiz("""
id: x
step_id: y
questions:
  - id: q
    type: multiple_choice
    prompt: p
    choices: {a: A, b: B}
    answer: z
""")
        assert "not in choices" in str(exc.value)

    def test_mc_needs_2_choices(self) -> None:
        with pytest.raises(QuizLoadError):
            parse_quiz("""
id: x
step_id: y
questions:
  - id: q
    type: multiple_choice
    prompt: p
    choices: {a: only}
    answer: a
""")

    def test_threshold_out_of_range_raises(self) -> None:
        with pytest.raises(QuizLoadError):
            parse_quiz("""
id: x
step_id: y
pass_threshold: 1.5
questions:
  - id: q
    prompt: p
    answer: a
    type: short_answer
""")

    def test_duplicate_question_ids_raise(self) -> None:
        with pytest.raises(QuizLoadError) as exc:
            parse_quiz("""
id: x
step_id: y
questions:
  - id: q1
    type: short_answer
    prompt: p1
    answer: a
  - id: q1
    type: short_answer
    prompt: p2
    answer: b
""")
        assert "duplicate question id" in str(exc.value)


class TestGrade:
    def setup_method(self) -> None:
        self.quiz = parse_quiz(SAMPLE_YAML)

    def test_all_correct_passes(self) -> None:
        result = grade(self.quiz, {"q1": "b", "q2": "%"})
        assert result.correct_count == 2
        assert result.total == 2
        assert result.score == 1.0
        assert result.passed is True

    def test_all_wrong_fails(self) -> None:
        result = grade(self.quiz, {"q1": "a", "q2": "x"})
        assert result.correct_count == 0
        assert result.score == 0.0
        assert result.passed is False

    def test_partial_above_threshold_passes(self) -> None:
        # 75% pass threshold means 1/2 = 50% should fail
        result = grade(self.quiz, {"q1": "b", "q2": "x"})
        assert result.correct_count == 1
        assert result.score == 0.5
        assert result.passed is False

    def test_short_answer_accepts_alternates(self) -> None:
        # "%." is in accept list
        result = grade(self.quiz, {"q1": "b", "q2": "%."})
        assert result.correct_count == 2
        assert result.passed is True

    def test_short_answer_case_insensitive(self) -> None:
        # Make a quiz with case_sensitive=False (the default)
        result = grade(self.quiz, {"q1": "B", "q2": "%"})
        assert result.correct_count == 2

    def test_short_answer_case_sensitive(self) -> None:
        text = """
id: x
step_id: y
questions:
  - id: q
    type: short_answer
    prompt: p
    answer: Foo
    case_sensitive: true
"""
        q = parse_quiz(text)
        assert grade(q, {"q": "Foo"}).correct_count == 1
        assert grade(q, {"q": "foo"}).correct_count == 0

    def test_missing_response_counts_wrong(self) -> None:
        result = grade(self.quiz, {})
        assert result.correct_count == 0
        assert result.per_question[0].response is None

    def test_per_question_carries_explain(self) -> None:
        result = grade(self.quiz, {"q1": "b", "q2": "%"})
        # q1 has an explain; q2 doesn't
        assert "append-only" in result.per_question[0].explain
        assert result.per_question[1].explain is None


class TestQuizRepo:
    def test_loads_from_explicit_path(self, tmp_path: Path) -> None:
        f = tmp_path / "bb" / "stage1" / "crtsh.yaml"
        f.parent.mkdir(parents=True)
        f.write_text(SAMPLE_YAML)
        repo = QuizRepo(search_paths=[tmp_path])
        all_quizzes = repo.all()
        assert "bb.stage1.crtsh" in all_quizzes
        q = repo.get("bb.stage1.crtsh")
        assert q.title == "CT Logs"

    def test_silently_skips_invalid_files(self, tmp_path: Path) -> None:
        f1 = tmp_path / "good.yaml"
        f1.write_text(SAMPLE_YAML)
        f2 = tmp_path / "bad.yaml"
        f2.write_text("just a string, not a mapping")
        repo = QuizRepo(search_paths=[tmp_path])
        all_quizzes = repo.all()
        assert len(all_quizzes) == 1

    def test_get_unknown_raises(self, tmp_path: Path) -> None:
        repo = QuizRepo(search_paths=[tmp_path])
        with pytest.raises(QuizNotFound):
            repo.get("bb.stage1.unknown")

    def test_packaged_quizzes_load(self) -> None:
        repo = QuizRepo()
        all_quizzes = repo.all()
        assert "bb.stage1.crtsh" in all_quizzes
        assert all_quizzes["bb.stage1.crtsh"].total >= 3
