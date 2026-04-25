"""Training mode: lessons, quizzes, and progress tracking.

The package layout mirrors the procedure YAML's ``training`` field:

  src/twisted/training/lessons/<procedure>/<stage>/<step>.md
  src/twisted/training/quizzes/<procedure>/<stage>/<step>.yaml

Lessons are markdown files with optional YAML frontmatter; quizzes are
YAML files with multiple-choice and short-answer questions. The
``extractor`` module bootstraps the lesson tree from the three docx
procedure manuals; quizzes are hand-curated.
"""

from .lessons import Lesson, LessonNotFound, LessonRepo
from .quizzes import (
    GradedQuestion,
    GradedQuiz,
    Question,
    Quiz,
    QuizNotFound,
    QuizRepo,
    grade,
)

__all__ = [
    "GradedQuestion",
    "GradedQuiz",
    "Lesson",
    "LessonNotFound",
    "LessonRepo",
    "Question",
    "Quiz",
    "QuizNotFound",
    "QuizRepo",
    "grade",
]
