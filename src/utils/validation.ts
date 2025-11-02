// Define a type for the profession categories
type ProfessionType =
  | "Student"
  | "IT Profession"
  | "Job Seeker"
  | "Aspirant Studying Abroad";

// Define the structure of the input fields
interface ProfessionFields {
  profession: ProfessionType;
  educationStatus?: string;
  schoolOrCollege?: string;
  organization?: string;
  qualification?: string;
}

/**
 * Utility to validate fields based on profession type.
 * Returns a string message if validation fails, or null if all good.
 */
export const validateProfessionFields = ({
  profession,
  educationStatus,
  schoolOrCollege,
  organization,
  qualification,
}: ProfessionFields): string | null => {
  const validationRules: Record<
    ProfessionType,
    { field: unknown; message: string }[]
  > = {
    Student: [
      {
        field: educationStatus,
        message: "Education status is required for students.",
      },
      {
        field: schoolOrCollege,
        message: "School or college is required for students.",
      },
    ],
    "IT Profession": [
      {
        field: organization,
        message: "Organization is required for IT professionals.",
      },
    ],
    "Job Seeker": [
      {
        field: qualification,
        message: "Qualification is required for job seekers.",
      },
    ],
    "Aspirant Studying Abroad": [
      {
        field: qualification,
        message: "Qualification is required for aspirants studying abroad.",
      },
    ],
  };

  const rules = validationRules[profession];

  if (!rules) {
    console.warn(`Invalid profession provided: ${profession}`);
    return "Invalid profession selected.";
  }

  for (const rule of rules) {
    if (!rule.field) {
      console.warn(`Validation failed: ${rule.message}`);
      return rule.message;
    }
  }

  return null; // ✅ All good
};
