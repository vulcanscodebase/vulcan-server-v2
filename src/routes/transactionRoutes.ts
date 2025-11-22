import express, { Router, type RequestHandler } from "express";
import { body, query } from "express-validator";

import {
  createTransaction,
  getAllTransactions,
  getUserTransactions,
  getPodTransactions,
  getTransactionById,
  getTransactionStats,
  getUserLicenseBalance,
} from "../controllers/transactionController.js";

import { protect } from "../middlewares/authMiddleware.js";
import validateRequest from "../middlewares/validateRequest.js";

const router: Router = express.Router();

// ✅ Global Auth Protection (All transaction endpoints require authentication)
router.use(protect as RequestHandler);

// ✅ Create Transaction (Assign or Deduct Licenses)
// Access: Users can create deduction for themselves, Admins can create for pod members, SuperAdmins can create for anyone
router.post(
  "/create",
  [
    body("type")
      .isIn(["assigned", "deducted"])
      .withMessage("Transaction type must be either 'assigned' or 'deducted'."),
    body("userId")
      .trim()
      .notEmpty()
      .withMessage("UserId is required.")
      .isMongoId()
      .withMessage("Invalid userId format."),
    body("amount")
      .isInt({ min: 1 })
      .withMessage("Amount must be a positive integer."),
    body("reason")
      .isIn([
        "Pod Assignment",
        "Interview Attendance",
        "Admin Adjustment",
        "Refund",
        "Bulk Assignment",
      ])
      .withMessage("Invalid transaction reason."),
    body("podId").optional().isMongoId().withMessage("Invalid podId format."),
    body("interviewId")
      .optional()
      .isMongoId()
      .withMessage("Invalid interviewId format."),
    body("description")
      .optional()
      .isString()
      .isLength({ max: 500 })
      .withMessage("Description cannot exceed 500 characters."),
  ],
  validateRequest as RequestHandler,
  createTransaction as unknown as RequestHandler
);

// ✅ Get All Transactions (with pagination and filters)
// Access: SuperAdmins only
router.get(
  "/all",
  [
    query("page")
      .optional()
      .isInt({ min: 1 })
      .withMessage("Page must be a positive integer."),
    query("limit")
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage("Limit must be between 1 and 100."),
    query("type")
      .optional()
      .isIn(["assigned", "deducted"])
      .withMessage("Invalid transaction type."),
    query("reason")
      .optional()
      .isIn([
        "Pod Assignment",
        "Interview Attendance",
        "Admin Adjustment",
        "Refund",
        "Bulk Assignment",
      ])
      .withMessage("Invalid reason."),
    query("status")
      .optional()
      .isIn(["completed", "pending", "cancelled"])
      .withMessage("Invalid status."),
    query("startDate")
      .optional()
      .isISO8601()
      .withMessage("startDate must be a valid ISO date."),
    query("endDate")
      .optional()
      .isISO8601()
      .withMessage("endDate must be a valid ISO date."),
  ],
  validateRequest as RequestHandler,
  getAllTransactions as unknown as RequestHandler
);

// ✅ Get User Transaction History
// Access: Users can view their own, SuperAdmins can view all
router.get(
  "/user/:userId",
  [
    query("page")
      .optional()
      .isInt({ min: 1 })
      .withMessage("Page must be a positive integer."),
    query("limit")
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage("Limit must be between 1 and 100."),
    query("type")
      .optional()
      .isIn(["assigned", "deducted"])
      .withMessage("Invalid transaction type."),
    query("reason")
      .optional()
      .isIn([
        "Pod Assignment",
        "Interview Attendance",
        "Admin Adjustment",
        "Refund",
        "Bulk Assignment",
      ])
      .withMessage("Invalid reason."),
    query("status")
      .optional()
      .isIn(["completed", "pending", "cancelled"])
      .withMessage("Invalid status."),
    query("startDate")
      .optional()
      .isISO8601()
      .withMessage("startDate must be a valid ISO date."),
    query("endDate")
      .optional()
      .isISO8601()
      .withMessage("endDate must be a valid ISO date."),
  ],
  validateRequest as RequestHandler,
  getUserTransactions as unknown as RequestHandler
);

// ✅ Get Pod Transactions
// Access: Admins managing the pod, SuperAdmins only
router.get(
  "/pod/:podId",
  [
    query("page")
      .optional()
      .isInt({ min: 1 })
      .withMessage("Page must be a positive integer."),
    query("limit")
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage("Limit must be between 1 and 100."),
    query("type")
      .optional()
      .isIn(["assigned", "deducted"])
      .withMessage("Invalid transaction type."),
    query("status")
      .optional()
      .isIn(["completed", "pending", "cancelled"])
      .withMessage("Invalid status."),
    query("startDate")
      .optional()
      .isISO8601()
      .withMessage("startDate must be a valid ISO date."),
    query("endDate")
      .optional()
      .isISO8601()
      .withMessage("endDate must be a valid ISO date."),
  ],
  validateRequest as RequestHandler,
  getPodTransactions as unknown as RequestHandler
);

// ✅ Get Transaction Statistics (User or Pod)
// Access: Users can view their own stats, Admins can view pod stats they manage, SuperAdmins can view all
router.get("/stats/user/:userId", getTransactionStats as unknown as RequestHandler);

router.get("/stats/pod/:podId", getTransactionStats as unknown as RequestHandler);

// ✅ Get License Balance for User
// Access: Users can view their own balance, SuperAdmins can view all
router.get(
  "/balance/:userId",
  getUserLicenseBalance as unknown as RequestHandler
);

// ✅ Get Single Transaction by ID
// Access: Based on transaction association (pod or user)
router.get(
  "/:transactionId",
  getTransactionById as unknown as RequestHandler
);

export default router;
