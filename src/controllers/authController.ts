import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import type { Request, Response } from "express";
import axios from "axios";
import { User } from "../models/User.js";
import { Blacklist } from "../models/Blacklist.js";
import crypto from "crypto";
import { validateProfessionFields } from "../utils/validation.js";
import { sendEmail } from "../utils/email.js";

const JWT_SECRET = process.env.JWT_SECRET!;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET!;
const FRONTEND_URL = process.env.FRONTEND_URL!;
const BACKEND_URL = process.env.BACKEND_URL!;

// --- Local types & small helpers to satisfy typings used in this controller ---
type AuthRequest = Request & { user?: any; cookies?: any };

const maskToken = (token?: string | null) =>
  token ? String(token).slice(0, 10) + "..." : "None";

const getCookieOptions = () => {
  const isProduction = process.env.NODE_ENV === "production";
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? ("none" as "none" | "lax") : "lax",
    domain: isProduction ? ".vulcans.in" : undefined,
    path: "/",
  } as any;
};

const clearTokens = (res: Response) => {
  const cookieOptions = getCookieOptions();
  res.clearCookie("accessToken", cookieOptions);
  res.clearCookie("refreshToken", cookieOptions);
};

const blacklistToken = async (token: string, secret?: string) => {
  try {
    let decoded: any = null;
    try {
      decoded = jwt.verify(token, secret || JWT_SECRET) as any;
    } catch (e) {
      // If token cannot be decoded, still store it with a short expiry to avoid reuse
      await Blacklist.create({
        token,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      });
      return;
    }

    if (decoded && decoded.exp) {
      const expiration = new Date(decoded.exp * 1000);
      await Blacklist.create({ token, expiresAt: expiration });
    } else {
      await Blacklist.create({
        token,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      });
    }
  } catch (err) {
    console.error("Error blacklisting token:", (err as any).message || err);
  }
};

// 🧩 REGISTER USER
export const registerUser = async (req: Request, res: Response) => {
  const { name, dob, email, password } = req.body;

  try {
    if (!name || name.trim().length < 3) {
      return res
        .status(400)
        .json({ message: "Name must be at least 3 characters long." });
    }
    if (!dob || isNaN(Date.parse(dob))) {
      return res
        .status(400)
        .json({ message: "A valid date of birth is required." });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
      return res
        .status(400)
        .json({ message: "A valid email address is required." });
    }
    if (!password || password.length < 8) {
      return res
        .status(400)
        .json({ message: "Password must be at least 8 characters long." });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists." });
    }

    const verificationToken = crypto.randomBytes(32).toString("hex");

    const newUser = new User({
      name,
      dob,
      email,
      password, // pre-save hook hashes it
      verified: false,
      verificationToken,
    });

    await newUser.save();

    const verificationUrl = `${BACKEND_URL}/api/auth/verify-email/${verificationToken}`;

    await sendEmail(
      newUser.email,
      "Verify Your Email",
      `Hi ${newUser.name},\n\nPlease verify your email by clicking the link below:\n\n${verificationUrl}\n\nThanks,\nVulcans Team`
    );

    return res.status(201).json({
      message:
        "User registered successfully. Please verify your email to activate your account.",
    });
  } catch (error: any) {
    console.error("Error registering user:", error.message);
    return res.status(500).json({ message: "Internal server error." });
  }
};

export const loginUser = async (req: AuthRequest, res: Response) => {
  const { email, password } = req.body;

  try {
    console.log("🔍 Login Attempt - Email:", email);

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required." });
    }

    const user = await User.findOne({ email });

    if (!user) {
      console.warn("⚠️ Login Failed - User Not Found:", email);
      return res.status(404).json({ message: "Invalid email or password." });
    }

    console.log("✅ User Found:", user.email);

    // ✅ Handle Google-registered users
    if (user.googleId && !user.password) {
      console.warn("⚠️ Login Failed - Google User Detected:", email);
      return res.status(400).json({
        message:
          "Your account is linked with Google. Please log in using Google.",
      });
    }

    // ✅ Handle invited users who haven't set a password yet
    if (!user.password && !user.googleId) {
      console.warn("⚠️ Login Failed - Password Not Set:", email);
      return res.status(403).json({
        message:
          "Your account was invited via email. Please set your password first using the setup link sent to your inbox.",
      });
    }

    console.log("🔄 Comparing Password...");
    const isPasswordValid = await bcrypt.compare(password, user.password || "");

    if (!isPasswordValid) {
      console.warn("❌ Login Failed - Incorrect Password:", email);
      return res.status(401).json({ message: "Invalid email or password." });
    }

    console.log("🔑 Password Matched! Generating Tokens...");

    // ✅ Clear old cookies
    clearTokens(res);

    const accessToken = jwt.sign(
      { id: user._id, isVerified: user.verified },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    const refreshToken = jwt.sign({ id: user._id }, JWT_REFRESH_SECRET, {
      expiresIn: "7d",
    });

    console.log("✅ Access Token:", maskToken(accessToken));
    console.log("✅ Refresh Token:", maskToken(refreshToken));

    const cookieOptions = getCookieOptions();
    res.cookie("accessToken", accessToken, {
      ...cookieOptions,
      maxAge: 60 * 60 * 1000,
    }); // 1 hour
    res.cookie("refreshToken", refreshToken, {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    }); // 7 days

    res.setHeader("x-access-token", accessToken);
    res.setHeader("x-refresh-token", refreshToken);

    console.log("✅ Login Successful - User:", user.email);

    return res.status(200).json({
      message: "Login successful.",
      accessToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        isVerified: user.verified,
        isProfileComplete: user.isProfileComplete,
      },
    });
  } catch (error: any) {
    console.error("❌ Error logging in user:", error.message);
    return res.status(500).json({ message: "Internal server error." });
  }
};

export const logoutUser = async (req: AuthRequest, res: Response) => {
  try {
    const accessToken = req.cookies?.accessToken;
    const refreshToken = req.cookies?.refreshToken;

    console.log("🔍 Logout Request Received");
    console.log(
      "🔑 Access Token:",
      accessToken ? accessToken.slice(0, 10) + "..." : "None"
    );
    console.log(
      "🔄 Refresh Token:",
      refreshToken ? refreshToken.slice(0, 10) + "..." : "None"
    );

    if (!accessToken && !refreshToken) {
      console.warn("⚠️ No tokens provided in cookies.");
      return res.status(400).json({ message: "No token provided." });
    }

    // 🔄 Blacklist Tokens if they exist
    if (accessToken) await blacklistToken(accessToken, JWT_SECRET);
    if (refreshToken) await blacklistToken(refreshToken, JWT_REFRESH_SECRET);

    // 🔄 Clear Cookies
    clearTokens(res);

    console.log("✅ Logout Successful: Tokens Blacklisted and Cookies Cleared");
    return res.status(200).json({ message: "Logout successful" });
  } catch (error: any) {
    console.error("❌ Error during logout:", error.message);
    return res.status(500).json({ message: "Internal server error." });
  }
};

export const forgotPassword = async (req: AuthRequest, res: Response) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Check if a valid token already exists
    if (
      user.resetPasswordToken &&
      user.resetPasswordExpire &&
      // resetPasswordExpire stored as Date
      (user.resetPasswordExpire as Date).getTime() > Date.now()
    ) {
      return res.status(400).json({
        message:
          "Verification email already sent. Please wait until it expires before requesting again.",
      });
    }

    // Generate a reset token
    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    // Store the hashed token in the database with expiration
    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpire = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes expiration
    await user.save();

    const resetUrl = `${process.env.FRONTEND_URL}/auth/reset-password/${resetToken}`;
    await sendEmail(
      user.email,
      "Password Reset Request",
      `You requested a password reset. Please click the link below to reset your password:\n\n${resetUrl}`
    );

    res.status(200).json({ message: "Password reset email sent." });
  } catch (error: any) {
    console.error("Error during password reset:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
};

export const resetPassword = async (req: AuthRequest, res: Response) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    if (!password) {
      return res.status(400).json({ message: "Password is required" });
    }

    if (!token) {
      return res.status(400).json({ message: "Token is required" });
    }

    // Hash the incoming token for comparison
    const hashedToken = crypto
      .createHash("sha256")
      .update(String(token))
      .digest("hex");

    // Find the user by hashed token and ensure it has not expired
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    // Debugging Logs
    console.log("New Password Before Hashing:", password);

    // Assign plain password (pre-save hook in `User.js` will hash it automatically)
    user.password = password;
    user.resetPasswordToken = null;
    user.resetPasswordExpire = null;

    await user.save(); // Pre-save hook in `User.js` will hash before storing

    console.log("Password reset successfully for user:", user.email);
    res.status(200).json({ message: "Password reset successfully" });
  } catch (error: any) {
    console.error("Error resetting password:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
};

export const changePassword = async (req: AuthRequest, res: Response) => {
  const { oldPassword, newPassword } = req.body;

  try {
    // Ensure user is authenticated
    const userId = req.user?.id; // Extracted from the JWT in the middleware
    if (!userId) {
      return res.status(401).json({
        message: "Unauthorized. Please log in to change your password.",
      });
    }

    // Validate input
    if (!oldPassword || !newPassword) {
      return res
        .status(400)
        .json({ message: "Both old and new passwords are required." });
    }
    if (newPassword.length < 8) {
      return res
        .status(400)
        .json({ message: "New password must be at least 8 characters long." });
    }

    // Find the user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Verify the old password
    const isPasswordValid = await bcrypt.compare(
      oldPassword,
      user.password || ""
    );
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Old password is incorrect." });
    }

    // Hash the new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password
    user.password = hashedNewPassword;
    await user.save();

    res.status(200).json({ message: "Password changed successfully." });
  } catch (error: any) {
    console.error("Error changing password:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
};

export const refreshToken = async (req: AuthRequest, res: Response) => {
  try {
    const oldRefreshToken = req.cookies?.refreshToken;

    console.log("🔍 Received Refresh Token from Cookies:", oldRefreshToken);

    if (!oldRefreshToken) {
      console.warn("⚠️ Refresh token missing in cookies.");
      return res.status(401).json({ message: "Refresh token missing." });
    }

    // ✅ Environment Settings
    const isProduction = process.env.NODE_ENV === "production";
    const sameSitePolicy: "none" | "lax" = isProduction ? "none" : "lax";
    const cookieOptions = {
      httpOnly: true,
      secure: isProduction,
      sameSite: sameSitePolicy,
      domain: isProduction ? ".vulcans.in" : undefined,
      path: "/", // ✅ Ensure cookies are available site-wide
    } as any;

    // ✅ Check if refresh token is blacklisted
    const isBlacklisted = await Blacklist.findOne({ token: oldRefreshToken });
    if (isBlacklisted) {
      console.warn("⚠️ Blacklisted refresh token used.");
      res.clearCookie("refreshToken", cookieOptions);
      res.clearCookie("accessToken", cookieOptions);
      return res
        .status(403)
        .json({ message: "Refresh token has been invalidated." });
    }

    let decoded: any;
    try {
      decoded = jwt.verify(oldRefreshToken, JWT_REFRESH_SECRET);
    } catch (error: any) {
      console.error("❌ Invalid refresh token:", error.message);
      res.clearCookie("refreshToken", cookieOptions);
      res.clearCookie("accessToken", cookieOptions);
      return res
        .status(401)
        .json({ message: "Invalid or expired refresh token." });
    }

    console.log("✅ Refresh Token Decoded:", decoded);

    // ✅ Check if user exists
    const user = await User.findById(decoded.id);
    if (!user) {
      console.warn("❌ User not found. Clearing cookies.");
      res.clearCookie("refreshToken", cookieOptions);
      res.clearCookie("accessToken", cookieOptions);
      return res.status(404).json({ message: "User not found." });
    }

    // ✅ Blacklist old refresh token
    const expiration = new Date(decoded.exp * 1000);
    await Blacklist.create({ token: oldRefreshToken, expiresAt: expiration });

    // ✅ Generate new tokens
    const newAccessToken = jwt.sign(
      { id: user._id, isVerified: user.verified },
      JWT_SECRET,
      { expiresIn: "1h" }
    );
    const newRefreshToken = jwt.sign({ id: user._id }, JWT_REFRESH_SECRET, {
      expiresIn: "7d",
    });

    // ✅ Clear old cookies
    res.clearCookie("accessToken", cookieOptions);
    res.clearCookie("refreshToken", cookieOptions);

    // ✅ Set new cookies
    res.cookie("accessToken", newAccessToken, {
      ...cookieOptions,
      maxAge: 60 * 60 * 1000,
    });
    res.cookie("refreshToken", newRefreshToken, {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    console.log("✅ New Tokens Issued");

    return res.status(200).json({
      message: "Token refreshed successfully.",
      accessToken: newAccessToken,
    });
  } catch (error: any) {
    console.error("❌ Error refreshing token:", error.message);
    return res.status(500).json({ message: "Internal server error." });
  }
};

export const validateToken = async (req: AuthRequest, res: Response) => {
  try {
    const token =
      req.headers.authorization?.split(" ")[1] || req.cookies?.accessToken;
    console.log("🔍 Validating Token:", maskToken(token));

    if (!token) {
      console.warn("⚠️ Token is missing.");
      return res.status(400).json({ message: "Token is required." });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET) as any;
    } catch (error: any) {
      console.error("❌ Invalid token:", error.message);
      if (error.name === "JsonWebTokenError") {
        return res.status(401).json({ message: "Invalid token." });
      }
      if (error.name === "TokenExpiredError") {
        return res.status(401).json({ message: "Token has expired." });
      }
      return res.status(500).json({ message: "Internal server error." });
    }

    // ✅ Check if the token is blacklisted
    const isBlacklisted = await Blacklist.findOne({ token });
    if (isBlacklisted) {
      console.warn("⚠️ Token is blacklisted.");
      const cookieOptions = getCookieOptions();
      res.clearCookie("accessToken", cookieOptions);
      res.clearCookie("refreshToken", cookieOptions);
      console.log("✅ Blacklisted token cookies cleared.");
      return res.status(401).json({ message: "Token has been invalidated." });
    }

    console.log("✅ Token is valid.");

    // ✅ Set Token in Response Header
    res.setHeader("x-access-token", token);

    return res.status(200).json({
      message: "Token is valid.",
      user: {
        id: decoded.id,
        isVerified: decoded.isVerified,
      },
    });
  } catch (error: any) {
    console.error("❌ Error validating token:", error.message);
    return res.status(500).json({ message: "Internal server error." });
  }
};

export const verifyEmail = async (req: AuthRequest, res: Response) => {
  const { token } = req.params;

  try {
    const user = await User.findOne({ verificationToken: token });

    if (!user) {
      return res.status(400).json({
        message:
          "Invalid or expired token. Please request a new verification email.",
      });
    }

    // ✅ Prevent duplicate verification errors
    if (user.verified) {
      return res.status(200).json({ message: "Email is already verified." });
    }

    user.verified = true;
    user.verificationToken = null;
    await user.save();

    return res
      .status(200)
      .json({ message: "Email verified successfully. You may now log in." });
  } catch (error: any) {
    console.error("Error verifying email:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
};

export const resendVerificationEmail = async (
  req: AuthRequest,
  res: Response
) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    if (user.verified) {
      return res.status(400).json({ message: "Email is already verified." });
    }

    // ✅ Generate new token if the old one is expired
    user.verificationToken = crypto.randomBytes(32).toString("hex");
    await user.save();

    // ✅ **Fix: Use FRONTEND_URL instead of BACKEND_URL**
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email/${user.verificationToken}`;

    await sendEmail(
      user.email,
      "Resend Verification Email",
      `Hi ${user.name},\n\nPlease verify your email by clicking the link below:\n\n${verificationUrl}`
    );

    res
      .status(200)
      .json({ message: "Verification email resent successfully." });
  } catch (error: any) {
    console.error("Error resending verification email:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
};

export const getAutocompleteSuggestions = async (
  req: AuthRequest,
  res: Response
) => {
  const { input } = req.query as any;

  if (!input) {
    return res.status(400).json({ message: "Input query is required." });
  }

  try {
    const apiKey = process.env.GOOGLE_API_KEY; // Ensure this is set in .env
    const url = `https://maps.googleapis.com/maps/api/place/autocomplete/json?input=${encodeURIComponent(
      input
    )}&types=establishment&key=${apiKey}`;

    const response = await axios.get(url);

    // Validate the Google API response
    if (response.data.status !== "OK") {
      return res.status(400).json({
        message: "Failed to fetch autocomplete suggestions.",
        error: response.data.status,
        details: response.data.error_message || null,
      });
    }

    // Filter and format predictions
    const suggestions = response.data.predictions.map((prediction: any) => ({
      description: prediction.description,
      placeId: prediction.place_id,
    }));

    res.status(200).json({ suggestions });
  } catch (error: any) {
    console.error("Error fetching autocomplete suggestions:", error.message);
    res
      .status(500)
      .json({ message: "Internal server error.", error: error.message });
  }
};

export const completeProfile = async (req: AuthRequest, res: Response) => {
  const {
    profession,
    educationStatus,
    schoolOrCollege,
    organization,
    qualification,
  } = req.body;

  try {
    // ✅ Ensure user is authenticated
    const userId = req.user?.id;
    if (!userId) {
      console.warn("⚠️ Unauthorized access - No user ID found in request.");
      return res.status(401).json({ message: "Unauthorized. Please log in." });
    }

    // ✅ Fetch user from database
    const user = await User.findById(userId);
    if (!user) {
      console.warn(`⚠️ User not found - ID: ${userId}`);
      return res.status(404).json({ message: "User not found." });
    }

    // ✅ Prevent profile update for unverified users
    if (!user.verified) {
      console.warn(
        `⚠️ Unauthorized profile update attempt - User not verified: ${user.email}`
      );
      return res.status(403).json({
        message: "Please verify your email before updating your profile.",
      });
    }

    // ✅ Allow Google users to update profile
    if (user.googleId) {
      console.log(`🔹 Google user updating profile: ${user.email}`);
    }

    // ✅ Validate profession-related fields
    const validationError = validateProfessionFields({
      profession,
      educationStatus,
      schoolOrCollege,
      organization,
      qualification,
    });

    if (validationError) {
      console.warn(`⚠️ Validation error: ${validationError}`);
      return res.status(400).json({ message: validationError });
    }

    // ✅ Update user profile fields
    user.profession = profession;
    user.educationStatus = profession === "Student" ? educationStatus : null;
    user.schoolOrCollege = profession === "Student" ? schoolOrCollege : null;
    user.organization = profession === "IT Profession" ? organization : null;
    user.qualification = ["Job Seeker", "Aspirant Studying Abroad"].includes(
      profession
    )
      ? qualification
      : null;

    // ✅ Save changes
    await user.save();
    console.log(`✅ Profile updated successfully for: ${user.email}`);

    res.status(200).json({
      message: "Profile updated successfully.",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        profession: user.profession,
        educationStatus: user.educationStatus,
        schoolOrCollege: user.schoolOrCollege,
        organization: user.organization,
        qualification: user.qualification,
      },
    });
  } catch (error: any) {
    console.error("❌ Error updating profile:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
};

export const getUserByToken = async (req: AuthRequest, res: Response) => {
  try {
    // ✅ Extract token from Authorization header or cookies
    const token =
      req.headers.authorization?.split(" ")[1] || req.cookies?.accessToken;
    console.log("🔍 Validating Token:", maskToken(token));

    if (!token) {
      console.warn("⚠️ No token provided.");
      return res.status(400).json({ message: "Token is required." });
    }

    // ✅ Verify the token
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET) as any;
    } catch (error: any) {
      console.error("❌ Token Verification Failed:", error.message);
      if (error.name === "JsonWebTokenError") {
        return res.status(401).json({ message: "Invalid token." });
      }
      if (error.name === "TokenExpiredError") {
        return res.status(401).json({ message: "Token has expired." });
      }
      return res.status(500).json({ message: "Internal server error." });
    }

    console.log("✅ Token Decoded:", {
      id: decoded.id,
      isVerified: decoded.isVerified,
    });

    // ✅ Check if the token is blacklisted
    const isBlacklisted = await Blacklist.findOne({ token });
    if (isBlacklisted) {
      console.warn("⚠️ Token is blacklisted.");
      const cookieOptions = getCookieOptions();
      res.clearCookie("accessToken", cookieOptions);
      res.clearCookie("refreshToken", cookieOptions);
      console.log("✅ Cleared Blacklisted Token Cookies.");
      return res.status(401).json({ message: "Token has been invalidated." });
    }

    // ✅ Fetch the user from the database
    const user = await User.findById(decoded.id).select(
      "-password -verificationToken"
    );
    if (!user) {
      console.warn("❌ User not found for ID:", decoded.id);
      return res.status(404).json({ message: "User not found." });
    }

    console.log("✅ User Retrieved Successfully:", user.email);

    // ✅ Set the token in the response header (for frontend use)
    res.setHeader("x-access-token", token);

    return res.status(200).json({
      message: "User fetched successfully.",
      user,
    });
  } catch (error: any) {
    console.error("❌ Error fetching user by token:", error.message);

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ message: "Invalid token." });
    }
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token has expired." });
    }

    return res.status(500).json({ message: "Internal server error." });
  }
};

export const handleGoogleCallback = async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user;

    console.log("🔍 Google User Authenticated:", user.email);

    // ✅ Generate JWT Tokens
    const accessToken = jwt.sign(
      { id: user._id, isVerified: user.verified },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    const refreshToken = jwt.sign({ id: user._id }, JWT_REFRESH_SECRET, {
      expiresIn: "7d",
    });

    console.log(
      "✅ Tokens Generated - Access:",
      maskToken(accessToken),
      "| Refresh:",
      maskToken(refreshToken)
    );

    // ✅ Define Cookie Options with Path
    const cookieOptions = getCookieOptions();

    // ✅ Clear Existing Cookies
    res.clearCookie("accessToken", cookieOptions);
    res.clearCookie("refreshToken", cookieOptions);

    // ✅ Check if previous tokens are blacklisted and clear if needed
    const isAccessBlacklisted = await Blacklist.findOne({ token: accessToken });
    const isRefreshBlacklisted = await Blacklist.findOne({
      token: refreshToken,
    });

    if (isAccessBlacklisted || isRefreshBlacklisted) {
      console.warn("⚠️ Detected blacklisted tokens, clearing cookies...");
      res.clearCookie("accessToken", cookieOptions);
      res.clearCookie("refreshToken", cookieOptions);
    }

    // ✅ Set Cookies for Tokens with Path
    res.cookie("accessToken", accessToken, {
      ...cookieOptions,
      maxAge: 60 * 60 * 1000,
    }); // 1 hour
    res.cookie("refreshToken", refreshToken, {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    }); // 7 days

    // ✅ Set Tokens in Response Headers
    res.setHeader("x-access-token", accessToken);
    res.setHeader("x-refresh-token", refreshToken);

    console.log(
      "✅ Google Login Successful - Tokens Set in Headers and Cookies"
    );

    // ✅ Redirect to Frontend with Tokens as Search Parameters
    const frontendUrl = process.env.FRONTEND_URL || "http://localhost:5173";
    const redirectUrl = `${frontendUrl}/?token=${encodeURIComponent(
      accessToken
    )}&refreshToken=${encodeURIComponent(refreshToken)}`;
    console.log("🔄 Redirecting to:", redirectUrl);
    res.redirect(redirectUrl);
  } catch (error: any) {
    console.error("❌ Error during Google callback:", error.message);
    res
      .status(500)
      .json({ message: "Internal Server Error", error: error.message });
  }
};

export const setupUserPassword = async (req: AuthRequest, res: Response) => {
  try {
    const { token, password } = req.body;

    if (!token || !password || password.trim().length < 8) {
      return res.status(400).json({
        message: "Valid token and password (min 8 characters) are required.",
      });
    }

    // Decode and verify token
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    const user = await User.findOne({ email: decoded.email });

    if (!user || user.verified) {
      return res.status(400).json({ message: "Invalid or expired token." });
    }

    // ✅ Set password directly — pre-save hook will hash it
    user.password = password;
    user.verificationToken = null;
    user.verified = true;

    await user.save();

    console.log(`✅ Password successfully set for user: ${user.email}`);
    res
      .status(200)
      .json({ message: "Password set successfully. You can now log in." });
  } catch (error: any) {
    console.error("❌ Error setting user password:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};
