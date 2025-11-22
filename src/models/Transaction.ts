import mongoose, { Document, Schema, Types } from "mongoose";
import {
  type TransactionType,
  type TransactionReason,
  TRANSACTION_TYPES,
  TRANSACTION_REASONS,
} from "../constants/enums.js";

export interface ITransaction extends Document {
  type: TransactionType; // "assigned" or "deducted"
  userId: Types.ObjectId; // Reference to User
  podId?: Types.ObjectId | null; // Reference to Pod (relevant for assignments)
  amount: number; // Number of licenses (positive value)
  reason: TransactionReason; // Why the transaction occurred
  description?: string | null; // Additional details about the transaction
  interviewId?: Types.ObjectId | null; // Reference to Interview (if deducted for interview)
  performedBy?: Types.ObjectId | null; // Reference to Admin who performed the action
  balanceAfter: number; // Balance after the transaction
  balanceBefore: number; // Balance before the transaction
  status?: "completed" | "pending" | "cancelled";
  metadata?: Record<string, unknown>; // Additional metadata if needed
  createdAt: Date;
  updatedAt: Date;
}

const transactionSchema = new Schema<ITransaction>(
  {
    type: {
      type: String,
      enum: TRANSACTION_TYPES,
      required: [true, "Transaction type is required."],
    },
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: [true, "User ID is required."],
    },
    podId: {
      type: Schema.Types.ObjectId,
      ref: "Pod",
      default: null,
    },
    amount: {
      type: Number,
      required: [true, "Amount is required."],
      min: [0, "Amount must be a positive number."],
    },
    reason: {
      type: String,
      enum: TRANSACTION_REASONS,
      required: [true, "Transaction reason is required."],
    },
    description: {
      type: String,
      default: null,
      trim: true,
      maxlength: [500, "Description cannot exceed 500 characters."],
    },
    interviewId: {
      type: Schema.Types.ObjectId,
      ref: "Interview",
      default: null,
    },
    performedBy: {
      type: Schema.Types.ObjectId,
      ref: "Admin",
      default: null,
    },
    balanceAfter: {
      type: Number,
      required: [true, "Balance after is required."],
      min: [0, "Balance cannot be negative."],
    },
    balanceBefore: {
      type: Number,
      required: [true, "Balance before is required."],
      min: [0, "Balance cannot be negative."],
    },
    status: {
      type: String,
      enum: ["completed", "pending", "cancelled"],
      default: "completed",
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
transactionSchema.index({ userId: 1 });
transactionSchema.index({ podId: 1 });
transactionSchema.index({ type: 1 });
transactionSchema.index({ reason: 1 });
transactionSchema.index({ createdAt: -1 });
transactionSchema.index({ interviewId: 1 });
transactionSchema.index({ performedBy: 1 });
// Compound indexes for common queries
transactionSchema.index({ userId: 1, createdAt: -1 });
transactionSchema.index({ userId: 1, type: 1 });
transactionSchema.index({ podId: 1, userId: 1 });
transactionSchema.index({ userId: 1, status: 1 });

// Pre-save validation - ensure balances are correct
transactionSchema.pre("save", async function (next) {
  const transaction = this as ITransaction;

  // Validate balance logic
  if (transaction.type === "assigned") {
    if (transaction.balanceAfter !== transaction.balanceBefore + transaction.amount) {
      return next(
        new Error(
          "Invalid balance: assigned amount should be added to previous balance"
        )
      );
    }
  } else if (transaction.type === "deducted") {
    if (transaction.balanceAfter !== transaction.balanceBefore - transaction.amount) {
      return next(
        new Error(
          "Invalid balance: deducted amount should be subtracted from previous balance"
        )
      );
    }
    if (transaction.balanceBefore < transaction.amount) {
      return next(
        new Error(
          "Insufficient licenses: cannot deduct more than current balance"
        )
      );
    }
  }

  next();
});

export const Transaction = mongoose.model<ITransaction>(
  "Transaction",
  transactionSchema
);
