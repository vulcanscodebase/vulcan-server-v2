import mongoose, { Document, Schema, Types } from "mongoose";

export interface IInterview extends Document {
  userId: Types.ObjectId; // Reference to User
  jobRole?: string | null; // Job role for the interview
  startedAt: Date; // When interview started
  completedAt?: Date | null; // When interview was completed
  status: "started" | "in_progress" | "completed" | "abandoned"; // Interview status
  report?: {
    // Interview feedback/report
    strengths?: string[];
    improvements?: string[];
    tips?: string[];
    overallFeedback?: string;
    metrics?: Record<string, unknown>;
  } | null;
  audioUrl?: string | null; // URL to recorded audio/video
  transcript?: {
    // Interview transcript
    questions?: Array<{
      question: string;
      askedAt: Date;
    }>;
    answers?: Array<{
      answer: string;
      answeredAt: Date;
    }>;
  } | null;
  resume?: {
    // Resume information
    text?: string;
    fileName?: string;
    evaluation?: Record<string, unknown>;
  } | null;
  metadata?: Record<string, unknown>; // Additional metadata
  createdAt: Date;
  updatedAt: Date;
}

const interviewSchema = new Schema<IInterview>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: [true, "User ID is required."],
    },
    jobRole: {
      type: String,
      trim: true,
      maxlength: [100, "Job role cannot exceed 100 characters."],
      default: null,
    },
    startedAt: {
      type: Date,
      required: [true, "Start time is required."],
      default: Date.now,
    },
    completedAt: {
      type: Date,
      default: null,
    },
    status: {
      type: String,
      enum: ["started", "in_progress", "completed", "abandoned"],
      required: [true, "Status is required."],
      default: "started",
    },
    report: {
      type: {
        strengths: [String],
        improvements: [String],
        tips: [String],
        overallFeedback: String,
        metrics: Schema.Types.Mixed,
      },
      default: null,
    },
    audioUrl: {
      type: String,
      default: null,
      trim: true,
    },
    transcript: {
      type: {
        questions: [
          {
            question: String,
            askedAt: { type: Date, default: Date.now },
          },
        ],
        answers: [
          {
            answer: String,
            answeredAt: { type: Date, default: Date.now },
          },
        ],
      },
      default: null,
    },
    resume: {
      type: {
        text: String,
        fileName: String,
        evaluation: Schema.Types.Mixed,
      },
      default: null,
    },
    metadata: {
      type: Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
  }
);

// Indexes for efficient querying
interviewSchema.index({ userId: 1 });
interviewSchema.index({ status: 1 });
interviewSchema.index({ startedAt: -1 });
interviewSchema.index({ createdAt: -1 });
interviewSchema.index({ userId: 1, createdAt: -1 });
interviewSchema.index({ userId: 1, status: 1 });

export const Interview = mongoose.model<IInterview>(
  "Interview",
  interviewSchema
);
