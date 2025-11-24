import express, { Router, type RequestHandler } from "express";
import { body, param, query } from "express-validator";

import {
  startInterview,
  completeInterview,
  getInterviewDetails,
  getUserInterviews,
  abandonInterview,
  updateInterviewFeedback,
  getPodInterviewReports,
  getAllInterviewReports,
  getPodInterviewStatistics,
  deleteInterview,
} from "../controllers/interviewController.js";

import { protect } from "../middlewares/authMiddleware.js";
import validateRequest from "../middlewares/validateRequest.js";

const router: Router = express.Router();

// ✅ Global Auth Protection (All interview endpoints require authentication)
router.use(protect as RequestHandler);

/**
 * @route POST /api/interviews/start
 * @desc Start a new interview session
 * @access Private (Authenticated Users)
 */
router.post(
  "/start",
  [
    body("jobRole")
      .optional()
      .trim()
      .isLength({ max: 100 })
      .withMessage("Job role cannot exceed 100 characters."),
    body("resumeText")
      .optional()
      .trim()
      .isLength({ min: 10 })
      .withMessage("Resume text must be at least 10 characters."),
    body("resumeFileName")
      .optional()
      .trim()
      .isLength({ max: 255 })
      .withMessage("Resume file name cannot exceed 255 characters."),
  ],
  validateRequest,
  startInterview as RequestHandler
);

/**
 * @route POST /api/interviews/complete
 * @desc Complete an interview session and deduct license
 * @access Private (Authenticated Users)
 */
router.post(
  "/complete",
  [
    body("interviewId")
      .trim()
      .notEmpty()
      .withMessage("Interview ID is required.")
      .isMongoId()
      .withMessage("Invalid interview ID format."),
    body("report")
      .optional()
      .isObject()
      .withMessage("Report must be an object."),
    body("report.strengths")
      .optional()
      .isArray()
      .withMessage("Strengths must be an array."),
    body("report.improvements")
      .optional()
      .isArray()
      .withMessage("Improvements must be an array."),
    body("report.tips")
      .optional()
      .isArray()
      .withMessage("Tips must be an array."),
    body("report.overallFeedback")
      .optional()
      .trim()
      .isLength({ max: 2000 })
      .withMessage("Overall feedback cannot exceed 2000 characters."),
    body("transcript")
      .optional()
      .isObject()
      .withMessage("Transcript must be an object."),
    body("audioUrl")
      .optional()
      .trim()
      .isURL()
      .withMessage("Invalid audio URL format."),
  ],
  validateRequest,
  completeInterview as RequestHandler
);

/**
 * @route GET /api/interviews/:interviewId
 * @desc Get interview details
 * @access Private (User or Admin)
 */
router.get(
  "/:interviewId",
  [
    param("interviewId")
      .isMongoId()
      .withMessage("Invalid interview ID format."),
  ],
  validateRequest,
  getInterviewDetails as unknown as RequestHandler
);

/**
 * @route GET /api/interviews/user/:userId
 * @desc Get all interviews for a user
 * @access Private (User or Admin)
 */
router.get(
  "/user/:userId",
  [
    param("userId").isMongoId().withMessage("Invalid user ID format."),
    query("page")
      .optional()
      .isInt({ min: 1 })
      .withMessage("Page must be a positive integer."),
    query("limit")
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage("Limit must be between 1 and 100."),
  ],
  validateRequest,
  getUserInterviews as unknown as RequestHandler
);

/**
 * @route POST /api/interviews/:interviewId/abandon
 * @desc Abandon an interview session (without deducting license)
 * @access Private (User)
 */
router.post(
  "/:interviewId/abandon",
  [
    param("interviewId")
      .isMongoId()
      .withMessage("Invalid interview ID format."),
    body("reason")
      .optional()
      .trim()
      .isLength({ max: 500 })
      .withMessage("Reason cannot exceed 500 characters."),
  ],
  validateRequest,
  abandonInterview as unknown as RequestHandler
);


/**
 * @route PUT /api/interviews/:interviewId/feedback
 * @desc Update interview with feedback/report
 * @access Private (User or Admin)
 */
router.put(
  "/:interviewId/feedback",
  [
    param("interviewId")
      .isMongoId()
      .withMessage("Invalid interview ID format."),
    body("report")
      .optional()
      .isObject()
      .withMessage("Report must be an object."),
    body("report.strengths")
      .optional()
      .isArray()
      .withMessage("Strengths must be an array."),
    body("report.improvements")
      .optional()
      .isArray()
      .withMessage("Improvements must be an array."),
    body("report.tips")
      .optional()
      .isArray()
      .withMessage("Tips must be an array."),
    body("report.overallFeedback")
      .optional()
      .trim()
      .isLength({ max: 2000 })
      .withMessage("Overall feedback cannot exceed 2000 characters."),
  ],
  validateRequest,
  updateInterviewFeedback as unknown as RequestHandler
);

/**
 * @route GET /api/interviews/admin/all-reports
 * @desc Get all interview reports across all pods
 * @access Private (Admin/SuperAdmin only)
 */
router.get(
  "/admin/all-reports",
  [
    query("page")
      .optional()
      .isInt({ min: 1 })
      .withMessage("Page must be a positive integer."),
    query("limit")
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage("Limit must be between 1 and 100."),
    query("status")
      .optional()
      .isIn(["started", "in_progress", "completed", "abandoned"])
      .withMessage("Invalid status value."),
    query("podId")
      .optional()
      .isMongoId()
      .withMessage("Invalid pod ID format."),
  ],
  validateRequest,
  getAllInterviewReports as RequestHandler
);

/**
 * @route GET /api/interviews/admin/pod-statistics
 * @desc Get pod-wise interview statistics
 * @access Private (Admin/SuperAdmin only)
 */
router.get(
  "/admin/pod-statistics",
  getPodInterviewStatistics as RequestHandler
);

/**
 * @route GET /api/interviews/pod/:podId/reports
 * @desc Get all interview reports for a specific pod
 * @access Private (Admin/SuperAdmin only)
 */
router.get(
  "/pod/:podId/reports",
  [
    param("podId").isMongoId().withMessage("Invalid pod ID format."),
    query("page")
      .optional()
      .isInt({ min: 1 })
      .withMessage("Page must be a positive integer."),
    query("limit")
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage("Limit must be between 1 and 100."),
    query("status")
      .optional()
      .isIn(["started", "in_progress", "completed", "abandoned"])
      .withMessage("Invalid status value."),
  ],
  validateRequest,
  getPodInterviewReports as unknown as RequestHandler
);

/**
 * @route DELETE /api/interviews/:interviewId
 * @desc Delete an interview (Admin/SuperAdmin only)
 * @access Private (Admin/SuperAdmin only)
 */
router.delete(
  "/:interviewId",
  [
    param("interviewId")
      .isMongoId()
      .withMessage("Invalid interview ID format."),
  ],
  validateRequest,
  deleteInterview as unknown as RequestHandler
);

export default router;
