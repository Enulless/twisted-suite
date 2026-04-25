"""YAML quiz loader + grader.

Quiz file format (one quiz per step)::

    id: bb.stage1.crtsh.quiz
    step_id: bb.stage1.crtsh
    title: Certificate Transparency Log Harvesting
    pass_threshold: 0.7    # 70 percent — optional, default 0.7
    questions:

      - id: q1
        type: multiple_choice
        prompt: |
          What does CT (Certificate Transparency) do?
        choices:
          a: Encrypts SSL traffic
          b: Logs every issued SSL/TLS certificate to public, append-only logs
          c: Authenticates clients via mutual TLS
          d: Replaces DNS for HTTPS sites
        answer: b
        explain: |
          CT logs are public, append-only records of issued certificates.

      - id: q2
        type: short_answer
        prompt: |
          Which crt.sh search prefix matches every subdomain of a domain?
        answer: "%."
        accept:
          - "%"
          - "%.example.com"   # accepts the example form too
        case_sensitive: false

Grading:
- ``multiple_choice``: the chosen key must equal the ``answer`` key
  (case-insensitive on the key letters).
- ``short_answer``: the response must equal the ``answer`` (or any of
  the additional ``accept`` values), normalised by stripping whitespace
  and (when ``case_sensitive: false``, the default) lowercasing.

Score is ``(correct / total)``; pass = ``score >= pass_threshold``.
"""

from __future__ import annotations

import importlib.resources as resources
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import yaml

VALID_QUESTION_TYPES = {"multiple_choice", "short_answer"}


class QuizNotFound(KeyError):
    pass


class QuizLoadError(ValueError):
    pass


@dataclass
class Question:
    id: str
    type: str
    prompt: str
    answer: str
    choices: dict[str, str] = field(default_factory=dict)
    accept: list[str] = field(default_factory=list)
    case_sensitive: bool = False
    explain: str | None = None


@dataclass
class Quiz:
    id: str
    step_id: str
    title: str
    questions: list[Question]
    pass_threshold: float = 0.7
    source_path: Path | None = None

    @property
    def total(self) -> int:
        return len(self.questions)


@dataclass
class GradedQuestion:
    question_id: str
    correct: bool
    response: str | None
    expected: str
    explain: str | None = None


@dataclass
class GradedQuiz:
    quiz_id: str
    step_id: str
    correct_count: int
    total: int
    score: float            # 0.0..1.0
    passed: bool
    per_question: list[GradedQuestion]


# ──────────────────────────── Parsing ────────────────────────────


def _coerce_question(raw: dict, *, quiz_id: str) -> Question:
    qid = raw.get("id")
    if not qid:
        raise QuizLoadError(f"{quiz_id}: question missing 'id'")
    qtype = (raw.get("type") or "multiple_choice").lower()
    if qtype not in VALID_QUESTION_TYPES:
        raise QuizLoadError(f"{quiz_id}.{qid}: invalid type '{qtype}'")
    prompt = (raw.get("prompt") or "").strip()
    if not prompt:
        raise QuizLoadError(f"{quiz_id}.{qid}: missing 'prompt'")
    answer = raw.get("answer")
    if answer is None:
        raise QuizLoadError(f"{quiz_id}.{qid}: missing 'answer'")
    answer_str = str(answer).strip()
    if not answer_str:
        raise QuizLoadError(f"{quiz_id}.{qid}: empty 'answer'")
    choices: dict[str, str] = {}
    if qtype == "multiple_choice":
        raw_choices = raw.get("choices") or {}
        if not isinstance(raw_choices, dict) or len(raw_choices) < 2:
            raise QuizLoadError(
                f"{quiz_id}.{qid}: multiple_choice needs >= 2 'choices'"
            )
        choices = {str(k).strip().lower(): str(v).strip()
                   for k, v in raw_choices.items()}
        if answer_str.lower() not in choices:
            raise QuizLoadError(
                f"{quiz_id}.{qid}: 'answer' {answer_str!r} not in choices "
                f"{sorted(choices)}"
            )
        answer_str = answer_str.lower()
    accept = [str(a) for a in (raw.get("accept") or [])]
    return Question(
        id=str(qid), type=qtype, prompt=prompt,
        answer=answer_str, choices=choices, accept=accept,
        case_sensitive=bool(raw.get("case_sensitive", False)),
        explain=(raw.get("explain") or "").strip() or None,
    )


def parse_quiz(text: str, *, source: Path | None = None) -> Quiz:
    raw = yaml.safe_load(text)
    if not isinstance(raw, dict):
        raise QuizLoadError(f"{source or '<inline>'}: must be a YAML mapping")
    qid = raw.get("id")
    step_id = raw.get("step_id")
    if not qid or not step_id:
        raise QuizLoadError(f"{source or '<inline>'}: requires 'id' and 'step_id'")
    title = raw.get("title") or step_id
    threshold = float(raw.get("pass_threshold", 0.7))
    if not 0.0 <= threshold <= 1.0:
        raise QuizLoadError(f"{qid}: pass_threshold must be in [0.0, 1.0]")
    raw_qs = raw.get("questions") or []
    if not raw_qs:
        raise QuizLoadError(f"{qid}: at least one question required")
    questions = [_coerce_question(q, quiz_id=qid) for q in raw_qs]
    seen_ids: set[str] = set()
    for q in questions:
        if q.id in seen_ids:
            raise QuizLoadError(f"{qid}: duplicate question id '{q.id}'")
        seen_ids.add(q.id)
    return Quiz(id=qid, step_id=step_id, title=title,
                questions=questions, pass_threshold=threshold,
                source_path=source)


# ──────────────────────────── Grading ────────────────────────────


def _normalise(value: str, *, case_sensitive: bool) -> str:
    s = (value or "").strip()
    return s if case_sensitive else s.lower()


def grade(quiz: Quiz, responses: dict[str, str]) -> GradedQuiz:
    """Grade a set of responses against ``quiz``.

    ``responses`` maps ``question.id`` to the user's submitted string
    (the chosen choice key for multiple_choice, or the typed string
    for short_answer). Missing responses count as incorrect.
    """
    per_q: list[GradedQuestion] = []
    correct = 0
    for q in quiz.questions:
        raw = responses.get(q.id)
        graded = _grade_one(q, raw)
        per_q.append(graded)
        if graded.correct:
            correct += 1
    total = quiz.total
    score = (correct / total) if total else 0.0
    return GradedQuiz(
        quiz_id=quiz.id, step_id=quiz.step_id,
        correct_count=correct, total=total, score=score,
        passed=score >= quiz.pass_threshold,
        per_question=per_q,
    )


def _grade_one(q: Question, raw: str | None) -> GradedQuestion:
    if raw is None:
        return GradedQuestion(question_id=q.id, correct=False, response=None,
                              expected=q.answer, explain=q.explain)
    response = str(raw)
    if q.type == "multiple_choice":
        ok = response.strip().lower() == q.answer
        return GradedQuestion(question_id=q.id, correct=ok, response=response,
                              expected=q.answer, explain=q.explain)
    # short_answer
    target = _normalise(q.answer, case_sensitive=q.case_sensitive)
    candidates = {target} | {_normalise(a, case_sensitive=q.case_sensitive)
                              for a in q.accept}
    ok = _normalise(response, case_sensitive=q.case_sensitive) in candidates
    return GradedQuestion(question_id=q.id, correct=ok, response=response,
                          expected=q.answer, explain=q.explain)


# ──────────────────────────── Repository ────────────────────────────


class QuizRepo:
    """Discovers and caches quiz files."""

    def __init__(self, search_paths: list[Path] | None = None):
        self._search_paths: list[Path] = list(search_paths or [])
        self._cache: dict[str, Quiz] | None = None

    def _discover_files(self) -> Iterator[Path]:
        for root in self._search_paths:
            if root.is_file() and root.suffix in (".yaml", ".yml"):
                yield root
            elif root.is_dir():
                yield from sorted(root.rglob("*.yaml"))
                yield from sorted(root.rglob("*.yml"))
        if not self._search_paths:
            try:
                pkg = resources.files("twisted.training.quizzes")
                yield from _walk_pkg(pkg)
            except (FileNotFoundError, ModuleNotFoundError):
                return

    def all(self) -> dict[str, Quiz]:
        """Returns ``step_id → Quiz`` (one quiz per step)."""
        if self._cache is not None:
            return self._cache
        out: dict[str, Quiz] = {}
        for path in self._discover_files():
            try:
                q = parse_quiz(path.read_text(encoding="utf-8"), source=path)
            except (OSError, QuizLoadError, yaml.YAMLError):
                continue
            out[q.step_id] = q
        self._cache = out
        return out

    def get(self, step_id: str) -> Quiz:
        quizzes = self.all()
        if step_id not in quizzes:
            raise QuizNotFound(step_id)
        return quizzes[step_id]

    def reload(self) -> None:
        self._cache = None


def _walk_pkg(traversable) -> Iterator[Path]:
    for entry in traversable.iterdir():
        try:
            if entry.is_dir():
                yield from _walk_pkg(entry)
            elif entry.is_file() and (entry.name.endswith(".yaml")
                                       or entry.name.endswith(".yml")):
                yield Path(str(entry))
        except (FileNotFoundError, NotADirectoryError):
            continue
