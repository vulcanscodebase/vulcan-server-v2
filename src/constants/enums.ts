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

/**
 * Transaction Type enum values
 */
export const TRANSACTION_TYPES = ["assigned", "deducted"] as const;

export type TransactionType = (typeof TRANSACTION_TYPES)[number];

/**
 * Transaction Reason enum values
 */
export const TRANSACTION_REASONS = [
  "Pod Assignment",
  "Interview Attendance",
  "Admin Adjustment",
  "Refund",
  "Bulk Assignment",
] as const;

export type TransactionReason = (typeof TRANSACTION_REASONS)[number];
