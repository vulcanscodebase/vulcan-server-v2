import { type Request, type Response } from "express";
import mongoose from "mongoose";
import { Transaction, type ITransaction } from "../models/Transaction.js";
import { User, type IUser } from "../models/User.js";
import { Pod } from "../models/Pod.js";
import {
  canAccessUserTransactions,
  canAccessPodTransactions,
  canCreateTransaction,
  canAccessTransaction,
} from "../utils/transactionAccess.js";

// 🧩 Types for request body
interface CreateTransactionBody {
  type: "assigned" | "deducted";
  userId: string;
  podId?: string;
  amount: number;
  reason:
    | "Pod Assignment"
    | "Interview Attendance"
    | "Admin Adjustment"
    | "Refund"
    | "Bulk Assignment";
  description?: string;
  interviewId?: string;
}

interface GetTransactionQueryParams {
  page?: string;
  limit?: string;
  type?: "assigned" | "deducted";
  reason?: string;
  startDate?: string;
  endDate?: string;
  status?: "completed" | "pending" | "cancelled";
}

/**
 * @desc Create a new transaction (assign or deduct licenses)
 * @route POST /api/transactions/create
 * @access Admin / SuperAdmin
 */
export const createTransaction = async (
  req: Request<{}, {}, CreateTransactionBody>,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const { type, userId, podId, amount, reason, description, interviewId } =
      req.body;

    // Validate required fields
    if (!type || !userId || !amount || !reason) {
      res.status(400).json({
        message: "Type, userId, amount, and reason are required.",
      });
      return;
    }

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      res.status(400).json({ message: "Invalid userId format." });
      return;
    }

    // ✅ Access Control: Check if requester can create transaction
    const hasAccess = await canCreateTransaction(requester, userId, podId);
    if (!hasAccess) {
      res.status(403).json({
        message: "You do not have permission to create this transaction.",
      });
      return;
    }

    // Fetch user
    const user = await User.findById(userId);
    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    // Validate pod if provided
    if (podId) {
      if (!mongoose.Types.ObjectId.isValid(podId)) {
        res.status(400).json({ message: "Invalid podId format." });
        return;
      }
      const pod = await Pod.findById(podId);
      if (!pod) {
        res.status(404).json({ message: "Pod not found." });
        return;
      }
    }

    // ✅ Enforce interviewId for "Interview Attendance" transactions
    if (reason === "Interview Attendance") {
      if (!interviewId || !mongoose.Types.ObjectId.isValid(interviewId)) {
        res.status(400).json({
          message: "Valid interviewId is required for 'Interview Attendance' transactions.",
        });
        return;
      }
    }

    // Calculate balance
    const balanceBefore = user.licenses || 0;
    let balanceAfter: number;

    if (type === "assigned") {
      balanceAfter = balanceBefore + amount;
    } else if (type === "deducted") {
      if (balanceBefore < amount) {
        res.status(400).json({
          message: `Insufficient licenses. User has ${balanceBefore} licenses but trying to deduct ${amount}.`,
        });
        return;
      }
      balanceAfter = balanceBefore - amount;
    } else {
      res.status(400).json({ message: "Invalid transaction type." });
      return;
    }

    // Create transaction
    const transaction = new Transaction({
      type,
      userId: new mongoose.Types.ObjectId(userId),
      podId: podId ? new mongoose.Types.ObjectId(podId) : null,
      amount,
      reason,
      description: description || null,
      interviewId: interviewId
        ? new mongoose.Types.ObjectId(interviewId)
        : null,
      performedBy: requester._id,
      balanceBefore,
      balanceAfter,
      status: "completed",
    });

    // Save transaction
    const savedTransaction = await transaction.save();

    // Update user's license balance
    user.licenses = balanceAfter;
    await user.save();

    res.status(201).json({
      message: "Transaction created successfully.",
      transaction: savedTransaction,
      userLicensesAfter: balanceAfter,
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error creating transaction.",
      error: errorMessage,
    });
  }
};

/**
 * @desc Get all transactions (with pagination and filters)
 * @route GET /api/transactions/all
 * @access Admin / SuperAdmin
 */
export const getAllTransactions = async (
  req: Request<{}, {}, {}, GetTransactionQueryParams>,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;

    // ✅ Access Control: Only SuperAdmins can view all transactions
    if (!requester.isSuperAdmin) {
      res.status(403).json({
        message:
          "Only SuperAdmins can view all transactions. Please use specific endpoints for your transactions or pod transactions.",
      });
      return;
    }

    const page = parseInt(req.query.page || "1", 10);
    const limit = parseInt(req.query.limit || "20", 10);
    const skip = (page - 1) * limit;

    // Build filters
    const filters: Record<string, unknown> = {};

    if (req.query.type) {
      filters.type = req.query.type;
    }

    if (req.query.reason) {
      filters.reason = req.query.reason;
    }

    if (req.query.status) {
      filters.status = req.query.status;
    }

    // Date range filter
    if (req.query.startDate || req.query.endDate) {
      filters.createdAt = {};
      if (req.query.startDate) {
        (filters.createdAt as Record<string, Date>).$gte = new Date(
          req.query.startDate
        );
      }
      if (req.query.endDate) {
        (filters.createdAt as Record<string, Date>).$lte = new Date(
          req.query.endDate
        );
      }
    }

    // Fetch transactions
    const transactions = await Transaction.find(filters)
      .populate("userId", "name email")
      .populate("podId", "name")
      .populate("performedBy", "email")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    // Get total count for pagination
    const total = await Transaction.countDocuments(filters);

    res.status(200).json({
      message: "Transactions fetched successfully.",
      transactions,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error fetching transactions.",
      error: errorMessage,
    });
  }
};

/**
 * @desc Get user's transaction history
 * @route GET /api/transactions/user/:userId
 * @access Admin / SuperAdmin / Self
 */
export const getUserTransactions = async (
  req: Request<{ userId: string }, {}, {}, GetTransactionQueryParams>,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const { userId } = req.params;
    const page = parseInt(req.query.page || "1", 10);
    const limit = parseInt(req.query.limit || "20", 10);
    const skip = (page - 1) * limit;

    // Validate userId
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      res.status(400).json({ message: "Invalid userId format." });
      return;
    }

    // Check if user exists
    const user = await User.findById(userId);
    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    // ✅ Access Control: Check if requester can access this user's transactions
    if (!canAccessUserTransactions(requester, userId)) {
      res.status(403).json({
        message:
          "You do not have permission to access this user's transactions.",
      });
      return;
    }

    // Build filters
    const filters: Record<string, unknown> = {
      userId: new mongoose.Types.ObjectId(userId),
    };

    if (req.query.type) {
      filters.type = req.query.type;
    }

    if (req.query.reason) {
      filters.reason = req.query.reason;
    }

    if (req.query.status) {
      filters.status = req.query.status;
    }

    // Date range filter
    if (req.query.startDate || req.query.endDate) {
      filters.createdAt = {};
      if (req.query.startDate) {
        (filters.createdAt as Record<string, Date>).$gte = new Date(
          req.query.startDate
        );
      }
      if (req.query.endDate) {
        (filters.createdAt as Record<string, Date>).$lte = new Date(
          req.query.endDate
        );
      }
    }

    // Fetch transactions
    const transactions = await Transaction.find(filters)
      .populate("podId", "name")
      .populate("performedBy", "email")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    // Get total count
    const total = await Transaction.countDocuments(filters);

    res.status(200).json({
      message: "User transactions fetched successfully.",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        currentLicenses: user.licenses,
      },
      transactions,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error fetching user transactions.",
      error: errorMessage,
    });
  }
};

/**
 * @desc Get transactions for a pod
 * @route GET /api/transactions/pod/:podId
 * @access Admin / SuperAdmin
 */
export const getPodTransactions = async (
  req: Request<{ podId: string }, {}, {}, GetTransactionQueryParams>,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const { podId } = req.params;
    const page = parseInt(req.query.page || "1", 10);
    const limit = parseInt(req.query.limit || "20", 10);
    const skip = (page - 1) * limit;

    // Validate podId
    if (!mongoose.Types.ObjectId.isValid(podId)) {
      res.status(400).json({ message: "Invalid podId format." });
      return;
    }

    // Check if pod exists
    const pod = await Pod.findById(podId);
    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    // ✅ Access Control: Check if requester can access this pod's transactions
    if (!canAccessPodTransactions(requester, pod)) {
      res.status(403).json({
        message:
          "You do not have permission to access this pod's transactions.",
      });
      return;
    }

    // Build filters
    const filters: Record<string, unknown> = {
      podId: new mongoose.Types.ObjectId(podId),
    };

    if (req.query.type) {
      filters.type = req.query.type;
    }

    if (req.query.status) {
      filters.status = req.query.status;
    }

    // Date range filter
    if (req.query.startDate || req.query.endDate) {
      filters.createdAt = {};
      if (req.query.startDate) {
        (filters.createdAt as Record<string, Date>).$gte = new Date(
          req.query.startDate
        );
      }
      if (req.query.endDate) {
        (filters.createdAt as Record<string, Date>).$lte = new Date(
          req.query.endDate
        );
      }
    }

    // Fetch transactions
    const transactions = await Transaction.find(filters)
      .populate("userId", "name email")
      .populate("performedBy", "email")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    // Get total count
    const total = await Transaction.countDocuments(filters);

    res.status(200).json({
      message: "Pod transactions fetched successfully.",
      pod: {
        id: pod._id,
        name: pod.name,
        type: pod.type,
      },
      transactions,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error fetching pod transactions.",
      error: errorMessage,
    });
  }
};

/**
 * @desc Get a single transaction by ID
 * @route GET /api/transactions/:transactionId
 * @access Admin / SuperAdmin
 */
export const getTransactionById = async (
  req: Request<{ transactionId: string }>,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const { transactionId } = req.params;

    // Validate transactionId
    if (!mongoose.Types.ObjectId.isValid(transactionId)) {
      res.status(400).json({ message: "Invalid transactionId format." });
      return;
    }

    // Fetch transaction
    const transaction = await Transaction.findById(transactionId)
      .populate("userId", "name email")
      .populate("podId", "name")
      .populate("performedBy", "email");

    if (!transaction) {
      res.status(404).json({ message: "Transaction not found." });
      return;
    }

    // ✅ Access Control: Check if requester can access this transaction
    const hasAccess = await canAccessTransaction(requester, transaction);
    if (!hasAccess) {
      res.status(403).json({
        message: "You do not have permission to access this transaction.",
      });
      return;
    }

    res.status(200).json({
      message: "Transaction fetched successfully.",
      transaction,
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error fetching transaction.",
      error: errorMessage,
    });
  }
};

/**
 * @desc Get transaction statistics for a user or pod
 * @route GET /api/transactions/stats/user/:userId
 * @route GET /api/transactions/stats/pod/:podId
 * @access Admin / SuperAdmin
 */
export const getTransactionStats = async (
  req: Request<{ userId?: string; podId?: string }>,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const { userId, podId } = req.params;

    let filters: Record<string, unknown> = {};

    if (userId) {
      if (!mongoose.Types.ObjectId.isValid(userId)) {
        res.status(400).json({ message: "Invalid userId format." });
        return;
      }

      // ✅ Access Control: Check if requester can access this user's stats
      if (!canAccessUserTransactions(requester, userId)) {
        res.status(403).json({
          message:
            "You do not have permission to access this user's statistics.",
        });
        return;
      }

      filters.userId = new mongoose.Types.ObjectId(userId);
    } else if (podId) {
      if (!mongoose.Types.ObjectId.isValid(podId)) {
        res.status(400).json({ message: "Invalid podId format." });
        return;
      }

      // ✅ Access Control: Check if requester can access this pod's stats
      const pod = await Pod.findById(podId);
      if (!pod) {
        res.status(404).json({ message: "Pod not found." });
        return;
      }

      if (!canAccessPodTransactions(requester, pod)) {
        res.status(403).json({
          message:
            "You do not have permission to access this pod's statistics.",
        });
        return;
      }

      filters.podId = new mongoose.Types.ObjectId(podId);
    } else {
      res.status(400).json({ message: "userId or podId is required." });
      return;
    }

    // Get aggregated stats
    const stats = await Transaction.aggregate([
      { $match: filters },
      {
        $group: {
          _id: "$type",
          total: { $sum: "$amount" },
          count: { $sum: 1 },
          avgAmount: { $avg: "$amount" },
        },
      },
    ]);

    // Get recent transactions
    const recentTransactions = await Transaction.find(filters)
      .sort({ createdAt: -1 })
      .limit(10)
      .populate("userId", "name email")
      .populate("podId", "name")
      .populate("performedBy", "email");

    res.status(200).json({
      message: "Transaction statistics fetched successfully.",
      stats,
      recentTransactions,
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error fetching transaction statistics.",
      error: errorMessage,
    });
  }
};

/**
 * @desc Get license balance for a user
 * @route GET /api/transactions/balance/:userId
 * @access Admin / SuperAdmin / Self
 */
export const getUserLicenseBalance = async (
  req: Request<{ userId: string }>,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const { userId } = req.params;

    // Validate userId
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      res.status(400).json({ message: "Invalid userId format." });
      return;
    }

    // Fetch user
    const user = await User.findById(userId).select("name email licenses");

    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    // ✅ Access Control: Check if requester can access this user's balance
    if (!canAccessUserTransactions(requester, userId)) {
      res.status(403).json({
        message:
          "You do not have permission to access this user's license balance.",
      });
      return;
    }

    // Get last transaction details
    const lastTransaction = await Transaction.findOne({
      userId: new mongoose.Types.ObjectId(userId),
    })
      .sort({ createdAt: -1 })
      .select("createdAt type reason amount");

    res.status(200).json({
      message: "License balance fetched successfully.",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        currentBalance: user.licenses || 0,
      },
      lastTransaction,
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error fetching license balance.",
      error: errorMessage,
    });
  }
};
