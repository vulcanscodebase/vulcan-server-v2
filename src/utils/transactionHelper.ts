import { Transaction, type ITransaction } from "../models/Transaction.js";
import { User } from "../models/User.js";
import mongoose from "mongoose";

/**
 * Record a license assignment transaction
 * @param userId - ID of the user receiving licenses
 * @param amount - Number of licenses being assigned
 * @param podId - ID of the pod (optional, for context)
 * @param performedBy - ID of the admin who performed the assignment
 * @param reason - Reason for assignment (defaults to "Pod Assignment")
 * @param description - Additional description of the transaction
 */
export const recordLicenseAssignment = async (
  userId: mongoose.Types.ObjectId,
  amount: number,
  podId: mongoose.Types.ObjectId | null | undefined,
  performedBy: mongoose.Types.ObjectId,
  reason: "Pod Assignment" | "Bulk Assignment" | "Admin Adjustment" = "Pod Assignment",
  description?: string
): Promise<ITransaction | null> => {
  try {
    if (amount <= 0) {
      console.warn("⚠️  License assignment amount must be greater than 0");
      return null;
    }

    const user = await User.findById(userId);
    if (!user) {
      console.error(`❌ User ${userId} not found for license assignment`);
      return null;
    }

    const balanceBefore = user.licenses || 0;
    const balanceAfter = balanceBefore + amount;

    const transaction = new Transaction({
      type: "assigned",
      userId,
      podId: podId || null,
      amount,
      reason,
      description: description || null,
      performedBy,
      balanceBefore,
      balanceAfter,
      status: "completed",
      metadata: {
        previousBalance: balanceBefore,
        newBalance: balanceAfter,
      },
    });

    const savedTransaction = await transaction.save();
    console.log(
      `✅ License assignment transaction recorded: ${amount} licenses assigned to user ${user.email}`
    );

    return savedTransaction;
  } catch (error) {
    console.error("❌ Error recording license assignment transaction:", error);
    return null;
  }
};

/**
 * Record a license deduction transaction
 * @param userId - ID of the user losing licenses
 * @param amount - Number of licenses being deducted
 * @param performedBy - ID of the admin who performed the deduction
 * @param reason - Reason for deduction
 * @param description - Additional description of the transaction
 * @param interviewId - ID of the interview (if deducted for interview attendance)
 */
export const recordLicenseDeduction = async (
  userId: mongoose.Types.ObjectId,
  amount: number,
  performedBy: mongoose.Types.ObjectId,
  reason: "Interview Attendance" | "Admin Adjustment" | "Refund" = "Admin Adjustment",
  description?: string,
  interviewId?: mongoose.Types.ObjectId
): Promise<ITransaction | null> => {
  try {
    if (amount <= 0) {
      console.warn("⚠️  License deduction amount must be greater than 0");
      return null;
    }

    const user = await User.findById(userId);
    if (!user) {
      console.error(`❌ User ${userId} not found for license deduction`);
      return null;
    }

    const balanceBefore = user.licenses || 0;

    if (balanceBefore < amount) {
      console.warn(
        `⚠️  Insufficient licenses for user ${user.email}: has ${balanceBefore}, needs to deduct ${amount}`
      );
      return null;
    }

    const balanceAfter = balanceBefore - amount;

    const transaction = new Transaction({
      type: "deducted",
      userId,
      amount,
      reason,
      description: description || null,
      interviewId: interviewId || null,
      performedBy,
      balanceBefore,
      balanceAfter,
      status: "completed",
      metadata: {
        previousBalance: balanceBefore,
        newBalance: balanceAfter,
      },
    });

    const savedTransaction = await transaction.save();
    console.log(
      `✅ License deduction transaction recorded: ${amount} licenses deducted from user ${user.email}`
    );

    return savedTransaction;
  } catch (error) {
    console.error("❌ Error recording license deduction transaction:", error);
    return null;
  }
};

/**
 * Get user's current license balance
 * @param userId - ID of the user
 */
export const getUserLicenseBalance = async (
  userId: mongoose.Types.ObjectId
): Promise<number> => {
  try {
    const user = await User.findById(userId);
    return user?.licenses || 0;
  } catch (error) {
    console.error("❌ Error fetching user license balance:", error);
    return 0;
  }
};
