import mongoose, { Schema, Document, Types } from "mongoose";

export interface IInvitedUser {
  email: string;
  invitedAt?: Date;
  status?: "pending" | "joined";
  userId?: Types.ObjectId | null;
}

export interface IActivityLog {
  action: string;
  message?: string;
  performedBy?: Types.ObjectId;
  timestamp?: Date;
}

export interface IPod extends Document {
  name: string;
  type: "institution" | "organization" | "private";
  institutionName?: string | null;
  educationStatus?: string | null;
  organizationName?: string | null;
  associatedEmail?: string | null;
  managedBy?: Types.ObjectId | null;
  invitedUsers: IInvitedUser[];
  activityLogs: IActivityLog[];
  lockProfile?: boolean;
  createdBy: Types.ObjectId;
  isDeleted: boolean;
  deletedAt?: Date | null;
  isArchived: boolean;
  archivedAt?: Date | null;
  tags?: string[];
  assignedTests?: Types.ObjectId[];
  assignedCourses?: Types.ObjectId[];
  createdAt: Date;
  updatedAt: Date;
}

const podSchema = new Schema<IPod>(
  {
    name: { type: String, required: true, trim: true, minlength: 3 },
    type: {
      type: String,
      enum: ["institution", "organization", "private"],
      default: "private",
    },
    institutionName: { type: String, default: null },
    organizationName: { type: String, default: null },
    educationStatus: { type: String, default: null },
    associatedEmail: { type: String, default: null },
    managedBy: { type: Schema.Types.ObjectId, ref: "Admin", default: null },
    invitedUsers: [
      {
        email: { type: String, required: true },
        invitedAt: { type: Date, default: Date.now },
        status: {
          type: String,
          enum: ["pending", "joined"],
          default: "pending",
        },
        userId: { type: Schema.Types.ObjectId, ref: "User", default: null },
      },
    ],
    activityLogs: [
      {
        action: { type: String, required: true },
        message: { type: String },
        performedBy: { type: Schema.Types.ObjectId, ref: "Admin" },
        timestamp: { type: Date, default: Date.now },
      },
    ],
    lockProfile: { type: Boolean, default: false },
    createdBy: { type: Schema.Types.ObjectId, ref: "Admin", required: true },
    isDeleted: { type: Boolean, default: false },
    deletedAt: { type: Date, default: null },
    isArchived: { type: Boolean, default: false },
    archivedAt: { type: Date, default: null },
    tags: { type: [String], default: [] },
    assignedTests: [{ type: Schema.Types.ObjectId, ref: "Test" }],
    assignedCourses: [{ type: Schema.Types.ObjectId, ref: "Course" }],
  },
  { timestamps: true }
);

podSchema.index({ name: 1 });
podSchema.index({ createdBy: 1 });
podSchema.index({ type: 1 });

export const Pod = mongoose.model<IPod>("Pod", podSchema);
