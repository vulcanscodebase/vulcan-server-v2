/**
 * Education Status enum values
 */
export const EDUCATION_STATUSES = [
  "10th or below",
  "11th-12th or diploma",
  "Undergrad",
  "Grad",
  "Post Grad",
] as const;

export type EducationStatus = (typeof EDUCATION_STATUSES)[number];

/**
 * Profession enum values
 */
export const PROFESSIONS = [
  "Student",
  "IT Profession",
  "Job Seeker",
  "Aspirant Studying Abroad",
] as const;

export type Profession = (typeof PROFESSIONS)[number];
