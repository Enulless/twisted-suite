import { get } from "./client";
import type { Worker } from "./types";

export const listWorkers = () => get<Worker[]>("/workers");
