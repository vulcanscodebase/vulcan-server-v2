import jwt from "jsonwebtoken";
import { type Request, type Response, type NextFunction } from "express";
import { User } from "../models/User.js";
import { Admin, type IAdmin } from "../models/Admin.js";
import { Blacklist } from "../models/Blacklist.js";
import { type IRole } from "../models/Role.js";

/**
 * Utility to send a standardized error response
 */
const sendErrorResponse = (
  res: Response,
  statusCode: number,
  message: string
) => {
  return res.status(statusCode).json({ success: false, message });
};

/**
 * Middleware: Protect routes using JWT authentication
 */
export const protect = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  console.log("🔍 protect middleware triggered");

  try {
    const token =
      req.cookies?.accessToken || req.headers.authorization?.split(" ")[1];

    if (!token)
      return sendErrorResponse(res, 401, "Unauthorized access. Please log in.");

    // 🔒 Check if token is blacklisted
    const isBlacklisted = await Blacklist.findOne({ token });
    if (isBlacklisted)
      return sendErrorResponse(res, 401, "Token is invalidated.");

    // 🧩 Verify token
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET as string
    ) as jwt.JwtPayload;

    const userId = decoded.userId;
    if (!userId)
      return sendErrorResponse(
        res,
        401,
        "Invalid token payload. Missing userId."
      );

    console.log("✅ Token verified for user ID:", userId);

    /**
     * 1️⃣ Try finding Admin
     */
    const admin: IAdmin & { role?: IRole } = await Admin.findById(userId)
      .populate("role", "name defaultPermissions")
      .select("-password");

    if (admin) {
      req.account = admin;
      req.role = admin.isSuperAdmin ? "super-admin" : "admin";
      req.isSuperAdmin = admin.isSuperAdmin;

      const rolePermissions = admin.role?.defaultPermissions || [];

      req.account.rolePermissions = Array.isArray(rolePermissions)
        ? rolePermissions
        : [];

      req.account.customPermissions = admin.customPermissions || [];
      req.account.extraPermissions = admin.extraPermissions || [];
      req.account.allowedToCreateRoles = admin.allowedToCreateRoles || [];
      req.account.canGrantExtraPermissions =
        admin.canGrantExtraPermissions || false;
      req.account.canCreateRoles = admin.canCreateRoles || false;
      req.account.canCreateUser = admin.canCreateUser || false;
      req.account.canUpdateUser = admin.canUpdateUser || false;
      req.account.canDeleteUser = admin.canDeleteUser || false;

      console.log(
        `🔹 Authenticated as ${req.role} (${admin.role?.name || "No Role"}): ${
          admin.email
        }`
      );
      return next();
    }

    /**
     * 2️⃣ Try finding User
     */
    const user = await User.findOne({
      $or: [{ _id: userId }, { googleId: userId }],
    }).select("-password");

    if (user) {
      req.account = user;
      req.role = "user";
      req.user = user;
      console.log(`🔹 Standard User Authenticated: ${user.email}`);
      return next();
    }

    // 🚫 No match found
    return sendErrorResponse(res, 404, "No account found for this token.");
  } catch (error: any) {
    console.error("❌ Error in protect middleware:", error);
    return sendErrorResponse(
      res,
      500,
      error.message || "Internal server error."
    );
  }
};

/**
 * Middleware: Restrict to verified users only
 */
export const requireVerifiedUser = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (!req.account || req.role !== "user" || !req.account.verified) {
    return sendErrorResponse(
      res,
      403,
      "Only verified users can access this route."
    );
  }
  next();
};
