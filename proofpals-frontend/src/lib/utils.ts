// src/lib/utils.ts
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";

// Combines conditional class names and merges Tailwind classes safely
export function cn(...inputs: Array<string | false | null | undefined>) {
  return twMerge(clsx(inputs));
}