import express, { Router } from "express";
import passport from "passport";
import rateLimit from "express-rate-limit";
import { body, param } from "express-validator";

import {
  registerUser,
  loginUser,
  logoutUser,
  forgotPassword,
  resetPassword,
  changePassword,
  refreshToken,
  validateToken,
  verifyEmail,
  resendVerificationEmail,
  getAutocompleteSuggestions,
  completeProfile,
  getUserByToken,
  handleGoogleCallback,
  setupUserPassword,
} from "../controllers/authController.js";

import { protect } from "../middlewares/authMiddleware.js";
import validateRequest from "../middlewares/validateRequest.js";

const router: Router = express.Router();

// ----------------------- Rate Limiting -----------------------
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP. Please try again later.",
});

// ----------------------- Public Routes ----------------------- //
router.post(
  "/register",
  authRateLimiter,
  [
    body("name").notEmpty().withMessage("Name is required."),
    body("email").isEmail().withMessage("Valid email is required."),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters long."),
  ],
  validateRequest,
  registerUser
);

router.get(
  "/verify-email/:token",
  [param("token").notEmpty().withMessage("Verification token is required.")],
  validateRequest,
  verifyEmail
);

router.post(
  "/resend-verification-email",
  [body("email").isEmail().withMessage("Valid email is required.")],
  validateRequest,
  resendVerificationEmail
);

router.post(
  "/login",
  authRateLimiter,
  [
    body("email").isEmail().withMessage("Valid email is required."),
    body("password").notEmpty().withMessage("Password is required."),
  ],
  validateRequest,
  loginUser
);

router.post(
  "/forgot-password",
  authRateLimiter,
  [body("email").isEmail().withMessage("Valid email is required.")],
  validateRequest,
  forgotPassword
);

router.post(
  "/reset-password/:token",
  authRateLimiter,
  [
    param("token").notEmpty().withMessage("Password reset token is required."),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters long."),
  ],
  validateRequest,
  resetPassword
);

router.post(
  "/setup-password",
  [
    body("token").notEmpty().withMessage("Token is required."),
    body("password")
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters long."),
  ],
  validateRequest,
  setupUserPassword
);

router.get("/user", protect, getUserByToken);

// -------------------- Google OAuth Login -------------------- //
router.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    session: false,
  })
);

router.get(
  "/google/callback",
  passport.authenticate("google", { session: false }),
  handleGoogleCallback
);

// -------------------- Protected Routes -------------------- //
router.post("/logout", protect, logoutUser);

router.post(
  "/complete-profile",
  protect,
  [
    body("profession")
      .isIn([
        "Student",
        "IT Profession",
        "Job Seeker",
        "Aspirant Studying Abroad",
      ])
      .withMessage("Invalid profession."),
  ],
  validateRequest,
  completeProfile
);

router.post(
  "/change-password",
  protect,
  [
    body("currentPassword")
      .notEmpty()
      .withMessage("Current password is required."),
    body("newPassword")
      .isLength({ min: 6 })
      .withMessage("New password must be at least 6 characters long."),
  ],
  validateRequest,
  changePassword
);

router.post("/refresh-token", refreshToken);
router.get("/validate-token", protect, validateToken);
router.get("/autocomplete", getAutocompleteSuggestions);

export default router;
