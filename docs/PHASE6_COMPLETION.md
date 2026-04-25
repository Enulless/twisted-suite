# Phase 6 — Completion Summary

**Status:** complete. **Tests:** 362/362 passing (+66 new training
tests). **Lint:** clean.

## What's working

The training mode is wired end-to-end:

- **Lesson tree** — 59 markdown lessons covering every step in all
  three procedure YAMLs, auto-extracted from the docx procedure
  manuals into `src/twisted/training/lessons/<procedure>/<stage>/<step>.md`.
  83% of steps got a real auto-matched lesson; the remainder ship as
  placeholders explaining the gap (one rebuild against an updated
  docx away from being filled).
- **Quiz engine** — YAML format with multiple-choice and short-answer
  question types, configurable pass thresholds, accepted-answer lists
  for short answers, optional case sensitivity, and per-question
  explanations. Grader returns a `GradedQuiz` with per-question
  results and a 0.0–1.0 score.
- **Sample quizzes** — 6 hand-curated quizzes shipped (bug-bounty
  stage 1 crtsh / dns_enum / email_security, stage 3 headers_audit,
  wp_stress phase 2 escalating, wifi phase 1 monitor_mode) to
  demonstrate the format and exercise the grader.
- **Progress tracking** — `training_progress` table holds one row per
  (user, lesson, quiz) with the latest score and timestamp; the unique
  constraint guarantees re-attempts replace prior rows rather than
  accumulate.
- **Engine API** — four endpoints under `/training`:

  | Method | Path | Returns |
  |---|---|---|
  | GET | `/training` | List of lesson summaries with completion status |
  | GET | `/training/{step_id}` | Full lesson body + quiz (answers hidden) + progress |
  | POST | `/training/{step_id}/quiz/submit` | Graded result + persisted progress |
  | GET | `/training/{step_id}/progress` | Last attempt for the user |

  The quiz JSON deliberately excludes the `answer` field on questions
  — only the server knows the correct answers, so a user can't
  inspect the network response and cheat.

- **CLI** — `twisted train list / show / quiz / extract / progress`
  with rich-rendered tables and an interactive quiz prompt. The
  `extract` subcommand rebuilds the lesson tree from .docx sources
  without needing the engine running.

- **Dashboard** — `/dashboard/training` index with per-procedure
  sections and completion checkmarks; `/dashboard/training/{step_id}`
  renders the lesson markdown to HTML and embeds the quiz form.
  Submitting the form posts via HTMX to a fragment endpoint that
  grades, persists, and returns a per-question breakdown that swaps
  in below the form. Nav link added to the base template.

- **Lesson extractor** — generic docx walker that collapses the
  three procedure manuals into a flat list of `DocxSection`s, then a
  per-step name-similarity matcher (token overlap + SequenceMatcher
  ratio, with manual overrides for steps whose YAML name differs
  significantly from the docx heading). Recursive section harvest so
  matching an H1 picks up its H2 children.

## What's NOT in Phase 6 (intentionally)

Per the plan callout, lab-integrated practice steps (the "practice
on the lab" button per step) require Phase 7's docker labs. The
extractor and quiz layer are ready for them; just need a UI that
pipes the step into the lab worker once those labs exist.

## Test coverage

| File | Tests | Covers |
|---|---:|---|
| `tests/unit/test_training_lessons.py` | 8 | frontmatter parser, section aliases, repo discovery, packaged-lessons load |
| `tests/unit/test_training_quizzes.py` | 18 | quiz schema validation (mc + short_answer), grader (correct / wrong / partial / case-sensitivity / missing responses), repo |
| `tests/unit/test_training_extractor.py` | 16 | similarity scoring, best-match w/ overrides, section→lesson conversion (H3 children, recursive H2-under-H1, "Why ..." prefix), markdown rendering |
| `tests/integration/test_training_api.py` | 10 | engine API end-to-end with a real FastAPI app, including answer-hiding, persistence, replace-on-resubmit, completion reflection, auth |
| `tests/integration/test_training_cli.py` | 5 | CLI smoke (list / show / progress / extract --help / filter) against a live engine on an ephemeral port |
| `tests/integration/test_training_dashboard.py` | 9 | dashboard index, filter, lesson detail, no-quiz fallback, quiz submit (pass + fail), completion in index, nav link |

Total: **66 new tests**, all passing.

## Quick start

```bash
twisted train list                          # all lessons w/ progress
twisted train show bb.stage1.crtsh          # render lesson to terminal
twisted train quiz bb.stage1.crtsh          # interactive quiz
twisted train progress                      # per-procedure summary
twisted train extract \                     # rebuild from your docx
    --bb /mnt/c/.../bug_bounty_procedure.docx \
    --wp /mnt/c/.../wp_stress_procedure.docx \
    --wifi /mnt/c/.../wifi_pentest_methodology.docx
```

In the dashboard:

- **/dashboard/training** — pick any lesson
- Read the auto-extracted markdown
- Take the quiz; results land instantly via HTMX
- Re-take any time; the latest score replaces the prior one

## Known limitations

- Six of the 59 lessons have hand-curated quizzes; the remaining 53
  show a "no quiz available" message. Adding more is just authoring
  YAML files under `src/twisted/training/quizzes/` — no code changes.
- 14% of auto-extracted lessons are placeholders (best name-match
  similarity below threshold). Add an entry to `STEP_NAME_OVERRIDES`
  in `extractor.py` and rerun `twisted train extract` to fix.
- The dashboard and CLI default the user to `default` / the OS
  username. Per-user accounts (with separate progress views) can be
  layered in later if the suite ever moves beyond solo use.
- The "Practice on the lab" button is deferred to Phase 7 alongside
  the docker labs.
