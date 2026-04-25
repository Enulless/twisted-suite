import { get, post } from "./client";
import type { LessonDetail, LessonSummary, QuizAttempt } from "./types";

export const listLessons = (user = "default", procedure?: string) =>
  get<LessonSummary[]>("/training", {
    user,
    ...(procedure ? { procedure } : {}),
  });

export const getLesson = (stepId: string, user = "default") =>
  get<LessonDetail>(`/training/${stepId}`, { user });

export const submitQuiz = (
  stepId: string,
  user: string,
  responses: Record<string, string>,
) =>
  post<QuizAttempt>(`/training/${stepId}/quiz/submit`, { user, responses });

export const getProgress = (stepId: string, user = "default") =>
  get<QuizAttempt | null>(`/training/${stepId}/progress`, { user });
