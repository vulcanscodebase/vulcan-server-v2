import { type Request, type Response } from "express";
import bcrypt from "bcryptjs";
import jwt, { type JwtPayload } from "jsonwebtoken";
import mongoose from "mongoose";
import { Admin, type IAdmin } from "../models/Admin.js";
import { Role, type IRole } from "../models/Role.js";
import { type IBlacklist, Blacklist } from "../models/Blacklist.js";
import { Pod } from "../models/Pod.js";
import { User } from "../models/User.js";
import { sendPasswordSetupEmail } from "../utils/email.js";

// 🧩 Types for request body
interface LoginRequestBody {
  email: string;
  password: string;
}

interface CreateRoleRequestBody {
  name: string;
  defaultPermissions: {
    feature: string;
    actions: ("view" | "create" | "edit" | "delete" | "publish")[];
  }[];
}

interface CreateAdminUserBody {
  name: string;
  email: string;
  role?: string;
  customPermissions?: {
    feature: string;
    actions: ("view" | "create" | "edit" | "delete" | "publish")[];
  }[];
  canCreateUser?: boolean;
  canUpdateUser?: boolean;
  canDeleteUser?: boolean;
  canCreateRoles?: boolean;
  isSuperAdmin?: boolean;
}

interface SetupPasswordBody {
  token: string;
  password: string;
}

interface SetupTokenPayload extends JwtPayload {
  email: string;
}

interface RefreshTokenPayload extends JwtPayload {
  id: string;
  exp: number;
}

// ✅ Admin Login
export const loginAdmin = async (
  req: Request<{}, {}, LoginRequestBody>,
  res: Response
): Promise<void> => {
  const { email, password } = req.body;

  try {
    console.log("🔍 Checking email:", email);

    const admin = await Admin.findOne({ email }).populate<{
      role: { name: string };
    }>("role");

    if (!admin) {
      console.log("❌ Admin not found for email:", email);
      res.status(404).json({ message: "Admin not found" });
      return;
    }
    console.log(admin);

    if (!password) {
      console.warn("⚠️ No password provided in request body");
      res.status(400).json({ message: "Password is required." });
      return;
    }

    if (!admin.password) {
      console.error("❌ Admin found but password is missing in DB:", email);
      res.status(500).json({
        message: "Password not set for this admin. Please contact support.",
      });
      return;
    }

    console.log("🔍 Fetched admin._id:", admin._id);
    console.log("🔑 Stored hashed password:", admin.password);

    console.log("Password from client:", JSON.stringify(password));
    console.log(
      "Password in .env:",
      JSON.stringify(process.env.SUPER_ADMIN_PASSWORD)
    );

    const isPasswordValid = await bcrypt.compare(password, admin.password);
    console.log("🔍 Password comparison result:", isPasswordValid);
    console.log(
      "Manual check:",
      await bcrypt.compare("Admin@123", admin.password)
    );

    if (!isPasswordValid) {
      console.log("❌ Invalid password for email:", email);
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    const isProduction = process.env.NODE_ENV === "production";
    const cookieOptions = {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? ("none" as const) : ("lax" as const),
      path: "/",
    };

    // 🛡️ JWT Tokens
    const accessToken = jwt.sign(
      {
        id: admin._id,
        isSuperAdmin: admin.isSuperAdmin,
        roleName: (admin.role as any)?.name || null,
      },
      process.env.JWT_SECRET as string,
      { expiresIn: "1h" }
    );

    const refreshToken = jwt.sign(
      { id: admin._id },
      process.env.JWT_REFRESH_SECRET as string,
      { expiresIn: "7d" }
    );

    // Optionally persist refresh token (if your model supports it)
    (admin as any).refreshToken = refreshToken;
    await admin.save();

    res.cookie("accessToken", accessToken, {
      ...cookieOptions,
      maxAge: 60 * 60 * 1000,
    });
    res.cookie("refreshToken", refreshToken, {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    console.log("✅ Login successful!");

    res.status(200).json({
      message: "Login successful",
      admin: {
        id: admin._id,
        name: admin.name,
        email: admin.email,
        isSuperAdmin: admin.isSuperAdmin,
        role: (admin.role as any)?.name || null,
      },
    });
  } catch (error) {
    console.error("❌ Error logging in admin:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

export const createRole = async (
  req: Request<{}, {}, CreateRoleRequestBody>,
  res: Response
): Promise<void> => {
  try {
    const { name, defaultPermissions } = req.body;
    const creator = req.account as IAdmin | undefined;

    if (!creator) {
      res
        .status(401)
        .json({ message: "Unauthorized: Admin not found in request." });
      return;
    }

    console.log(`🔍 Checking if ${creator.email} can create role: ${name}`);

    const hasPermission = creator.isSuperAdmin || creator.canCreateRoles;
    if (!hasPermission) {
      console.warn(
        `❌ ${creator.email} attempted to create role without permission`
      );
      res
        .status(403)
        .json({ message: "You do not have permission to create new roles." });
      return;
    }

    if (!name || typeof name !== "string" || name.trim().length < 3) {
      res
        .status(400)
        .json({ message: "Role name must be at least 3 characters long." });
      return;
    }

    const validActions = [
      "view",
      "create",
      "edit",
      "delete",
      "publish",
    ] as const;

    // 🧠 Validate defaultPermissions
    const isValidPermissions =
      Array.isArray(defaultPermissions) &&
      defaultPermissions.length > 0 &&
      defaultPermissions.every(
        (p) =>
          p.feature &&
          typeof p.feature === "string" &&
          Array.isArray(p.actions) &&
          p.actions.every((action) => validActions.includes(action))
      );

    if (!isValidPermissions) {
      res.status(400).json({
        message:
          "Invalid permissions format. Ensure correct feature and allowed actions.",
      });
      return;
    }

    const roleName = name.trim().toLowerCase();

    // 🔍 Check for duplicate role name
    const existingRole = await Role.findOne({ name: roleName });
    if (existingRole) {
      res
        .status(400)
        .json({ message: "A role with this name already exists." });
      return;
    }

    // 🧠 Permission scope validation (non-superadmin)
    if (!creator.isSuperAdmin) {
      const creatorPermissions = [
        ...(creator.rolePermissions || []),
        ...(creator.customPermissions || []),
      ];

      const hasFullAccess = creatorPermissions.some(
        (p) => p.feature === "all" && (p as any).accessLevel === "full"
      );

      const failedChecks: { feature: string; reason: string }[] = [];

      const canAssign = defaultPermissions.every((requested) => {
        if (hasFullAccess) return true;

        const matching = creatorPermissions.find(
          (cp) => cp.feature === requested.feature
        );
        if (!matching) {
          failedChecks.push({
            feature: requested.feature,
            reason: "Feature not present in your permissions",
          });
          return false;
        }

        const unauthorizedActions = requested.actions.filter(
          (a) => !matching.actions.includes(a)
        );

        if (unauthorizedActions.length > 0) {
          failedChecks.push({
            feature: requested.feature,
            reason: `Unauthorized actions: ${unauthorizedActions.join(", ")}`,
          });
          return false;
        }

        return true;
      });

      if (!canAssign) {
        console.warn(
          `❌ ${creator.email} tried to assign invalid permissions:`,
          failedChecks
        );
        res.status(403).json({
          message: "Permission assignment failed.",
          reason: "One or more permissions exceed your current scope.",
          failedPermissions: failedChecks,
        });
        return;
      }
    }

    // ✅ Create new role
    const newRole: IRole = await Role.create({
      name: roleName,
      defaultPermissions,
      createdBy: creator._id,
    });

    console.log(
      `✅ Role '${roleName}' created successfully by ${creator.email}`
    );

    res.status(201).json({
      message: "Role created successfully.",
      role: newRole,
    });
  } catch (error) {
    console.error("❌ Error creating role:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

export const createAdminUser = async (
  req: Request<{}, {}, CreateAdminUserBody>,
  res: Response
): Promise<void> => {
  try {
    const {
      name,
      email,
      role,
      customPermissions,
      canCreateUser,
      canUpdateUser,
      canDeleteUser,
      canCreateRoles,
      isSuperAdmin,
    } = req.body;

    const creator = req.account as IAdmin | undefined;

    if (!creator) {
      res
        .status(401)
        .json({ message: "Unauthorized: No admin found in request." });
      return;
    }

    console.log(
      `🔍 Checking if ${creator.email} can create user with role: ${role}`
    );
    console.log(`🔍 Super Admin Status: ${creator.isSuperAdmin}`);
    console.log(
      `🔍 Requested Custom Permissions:`,
      JSON.stringify(customPermissions, null, 2)
    );

    // 🚫 Prevent non-superadmin from creating another superadmin
    if (isSuperAdmin && !creator.isSuperAdmin) {
      res
        .status(403)
        .json({ message: "Only Super Admins can create another Super Admin." });
      return;
    }

    // 🚫 Permission to create roles check
    if (!creator.isSuperAdmin && !creator.canCreateRoles) {
      res
        .status(403)
        .json({ message: "You do not have permission to create roles." });
      return;
    }

    // ✅ Determine role permissions
    let rolePermissions: IAdmin["rolePermissions"] = [];

    if (isSuperAdmin) {
      rolePermissions = [
        {
          feature: "all",
          actions: ["view", "create", "edit", "delete", "publish"],
          isPermanent: true,
        },
      ];
    } else {
      const roleData = await Role.findById(role);
      if (!roleData) {
        res.status(400).json({ message: "The selected role does not exist." });
        return;
      }
      rolePermissions = roleData.defaultPermissions;
    }

    // ✅ Validate custom permissions (optional)
    let validatedCustomPermissions: IAdmin["customPermissions"] = [];

    if (
      customPermissions &&
      Array.isArray(customPermissions) &&
      customPermissions.length > 0
    ) {
      const isValid = customPermissions.every((p) => {
        const creatorPermission = creator.rolePermissions?.find(
          (cp) => cp.feature === p.feature
        );
        const hasFullAccess = creator.rolePermissions?.some(
          (cp) => cp.feature === "all" && (cp as any).accessLevel === "full"
        );
        if (hasFullAccess) return true;
        if (!creatorPermission) return false;
        return p.actions.every((action) =>
          creatorPermission.actions.includes(action)
        );
      });

      if (!isValid) {
        res.status(403).json({
          message: "Cannot assign custom permissions higher than your own.",
        });
        return;
      }

      validatedCustomPermissions = customPermissions;
    }

    // ✅ User management permission inheritance
    if (!creator.isSuperAdmin && !isSuperAdmin) {
      const isValidUserManagement =
        (!canCreateUser || creator.canCreateUser) &&
        (!canUpdateUser || creator.canUpdateUser) &&
        (!canDeleteUser || creator.canDeleteUser);

      if (!isValidUserManagement) {
        res.status(403).json({
          message: "Cannot assign user management rights higher than your own.",
        });
        return;
      }
    }

    // 🔍 Check for existing admin
    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      res
        .status(400)
        .json({ message: "An admin with this email already exists." });
      return;
    }

    // 🪙 Setup token for password creation link
    const setupToken = jwt.sign({ email }, process.env.JWT_SECRET as string, {
      expiresIn: "24h",
    });

    // ✅ Create new admin
    const newAdmin = new Admin({
      name,
      email,
      role: isSuperAdmin ? "super-admin" : role,
      isSuperAdmin: !!isSuperAdmin,
      rolePermissions,
      customPermissions: validatedCustomPermissions,
      canCreateUser: isSuperAdmin ? true : canCreateUser,
      canUpdateUser: isSuperAdmin ? true : canUpdateUser,
      canDeleteUser: isSuperAdmin ? true : canDeleteUser,
      canCreateRoles: isSuperAdmin ? true : canCreateRoles,
      canGrantExtraPermissions: isSuperAdmin ? true : false,
      password: undefined,
      passwordResetToken: setupToken,
      passwordResetExpires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });

    await newAdmin.save();

    // ✅ Send password setup email
    sendPasswordSetupEmail(name, email, setupToken);

    console.log(`✅ Admin '${email}' created successfully by ${creator.email}`);

    res.status(201).json({
      message: "Admin created. Password setup link will be sent to email.",
      admin: {
        id: newAdmin._id,
        name: newAdmin.name,
        email: newAdmin.email,
        isSuperAdmin: newAdmin.isSuperAdmin,
        role: newAdmin.role,
      },
    });
  } catch (error) {
    console.error("❌ Error creating admin:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

export const getAllAdmins = async (
  req: Request<{}, {}, {}, { role?: string }>, // Explicit query typing
  res: Response
): Promise<void> => {
  try {
    const requester = req.account as IAdmin | undefined;

    if (!requester) {
      res
        .status(401)
        .json({ message: "Unauthorized: No account found in request." });
      return;
    }

    console.log(`🔍 Fetching all admins for ${requester.email}`);

    const query: Record<string, any> = {};

    // ✅ Optional role filter from query param
    if (req.query.role) {
      query.role = req.query.role;
    }

    const admins = await Admin.find(query)
      .select("-password -passwordResetToken -passwordResetExpires")
      .populate("role", "name") // ✅ Only populate role name
      .sort({ createdAt: -1 })
      .lean(); // Optional: return plain objects for better performance

    console.log(`✅ Returning ${admins.length} admins`);

    res.status(200).json(admins);
  } catch (error) {
    console.error("❌ Error fetching all admins:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Delete an admin (Super Admin only)
 * @route DELETE /api/admin/:adminId
 * @access Private (Super Admin only)
 */
export const deleteAdmin = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account as IAdmin | undefined;
    const { adminId } = req.params as { adminId: string };

    if (!requester) {
      res.status(401).json({ message: "Unauthorized: No account found in request." });
      return;
    }

    // ✅ Only super admins can delete admins
    if (!requester.isSuperAdmin) {
      console.warn(`❌ ${requester.email} attempted to delete admin without super admin permission`);
      res.status(403).json({
        message: "Access denied. Only Super Admins can delete admin accounts.",
      });
      return;
    }

    // ✅ Validate adminId
    if (!mongoose.Types.ObjectId.isValid(adminId)) {
      res.status(400).json({ message: "Invalid admin ID format." });
      return;
    }

    // ✅ Find the admin to delete
    const adminToDelete = await Admin.findById(adminId);
    if (!adminToDelete) {
      res.status(404).json({ message: "Admin not found." });
      return;
    }

    // ✅ Prevent deleting yourself
    if (requester._id && requester._id.toString() === adminId) {
      res.status(400).json({
        message: "You cannot delete your own admin account. Please contact another super admin.",
      });
      return;
    }

    // ✅ Prevent deleting another super admin
    if (adminToDelete.isSuperAdmin) {
      res.status(400).json({
        message: "Cannot delete a Super Admin account. Only Super Admins can manage Super Admin accounts.",
      });
      return;
    }

    // ✅ Check if admin manages any pods
    const managedPods = await Pod.countDocuments({ managedBy: adminId });
    if (managedPods > 0) {
      res.status(400).json({
        message: `Cannot delete this admin. They are currently managing ${managedPods} pod(s). Please reassign or delete those pods first.`,
        managedPodsCount: managedPods,
      });
      return;
    }

    // ✅ Delete the admin
    await adminToDelete.deleteOne();

    console.log(`✅ Admin '${adminToDelete.email}' (ID: ${adminId}) deleted successfully by ${requester.email}`);

    res.status(200).json({
      message: `Admin '${adminToDelete.name}' has been successfully deleted.`,
      deletedAdmin: {
        id: adminToDelete._id,
        name: adminToDelete.name,
        email: adminToDelete.email,
        role: adminToDelete.role,
      },
    });
  } catch (error) {
    console.error("❌ Error deleting admin:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

export const setupPassword = async (
  req: Request<{}, {}, SetupPasswordBody>,
  res: Response
): Promise<void> => {
  try {
    const { token, password } = req.body;

    console.log("🟡 Token received:", token);
    console.log("🟡 Raw password received:", password);

    if (!token || !password || password.trim().length < 8) {
      res.status(400).json({
        message: "Valid token and password (min 8 characters) are required.",
      });
      return;
    }

    // ✅ Verify & decode token
    let decoded: SetupTokenPayload;
    try {
      decoded = jwt.verify(
        token,
        process.env.JWT_SECRET as string
      ) as SetupTokenPayload;
    } catch {
      res.status(400).json({ message: "Invalid or expired token." });
      return;
    }

    // ✅ Find admin by decoded email
    const admin = await Admin.findOne({ email: decoded.email });

    if (
      !admin ||
      admin.passwordResetToken !== token ||
      !admin.passwordResetExpires ||
      Date.now() > new Date(admin.passwordResetExpires).getTime()
    ) {
      res.status(400).json({ message: "Invalid or expired setup token." });
      return;
    }

    // ✅ Set new password (auto-hashed by pre-save hook)
    admin.password = password;
    admin.passwordResetToken = undefined;
    admin.passwordResetExpires = undefined;

    await admin.save();

    console.log(`✅ Password successfully set for admin: ${admin.email}`);

    res.status(200).json({
      message: "Password successfully set. You can now log in.",
    });
  } catch (error) {
    console.error("❌ Error setting up password:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

export const refreshTokenAdmin = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    // 🧠 Retrieve refresh token from cookie, body, or headers
    const oldRefreshToken: string | undefined =
      req.cookies?.refreshToken ||
      req.body?.refreshToken ||
      (req.headers["x-refresh-token"] as string | undefined);

    if (!oldRefreshToken) {
      console.warn("⚠️ Refresh token missing.");
      res.status(401).json({ message: "Refresh token missing." });
      return;
    }

    // ✅ Verify old refresh token
    let decoded: RefreshTokenPayload;
    try {
      decoded = jwt.verify(
        oldRefreshToken,
        process.env.JWT_REFRESH_SECRET as string
      ) as RefreshTokenPayload;
    } catch (error: any) {
      console.error("❌ Invalid refresh token:", error.message);
      res.status(401).json({ message: "Invalid or expired refresh token." });
      return;
    }

    // ✅ Lookup admin
    const admin = await Admin.findById(decoded.id);
    if (!admin) {
      res.status(404).json({ message: "Admin not found." });
      return;
    }

    // ✅ Blacklist old token (optional security layer)
    if (decoded.exp) {
      await Blacklist.create({
        token: oldRefreshToken,
        expiresAt: new Date(decoded.exp * 1000),
      });
    }

    // ✅ Generate new tokens
    const newAccessToken = jwt.sign(
      {
        id: admin._id,
        isSuperAdmin: admin.isSuperAdmin,
        role: admin.role,
      },
      process.env.JWT_SECRET as string,
      { expiresIn: "1h" }
    );

    const newRefreshToken = jwt.sign(
      { id: admin._id },
      process.env.JWT_REFRESH_SECRET as string,
      { expiresIn: "7d" }
    );

    (admin as any).refreshToken = newRefreshToken; // If not in IAdmin model
    await admin.save();

    // ✅ Set cookies (matching login settings)
    const isProduction = process.env.NODE_ENV === "production";
    const cookieOptions = {
      httpOnly: true,
      secure: isProduction,
      sameSite: (isProduction ? "none" : "lax") as "none" | "lax",
      domain: isProduction ? ".vulcans.in" : "localhost",
      path: "/",
    };

    res.cookie("accessToken", newAccessToken, {
      ...cookieOptions,
      maxAge: 60 * 60 * 1000, // 1 hour
    });

    res.cookie("refreshToken", newRefreshToken, {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    console.log("✅ New tokens issued after refresh.");

    res.status(200).json({
      message: "Token refreshed successfully.",
      accessToken: newAccessToken,
    });
  } catch (error) {
    console.error("❌ Error during token refresh:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

export const logoutAdmin = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { refreshToken } = req.cookies as { refreshToken?: string };

    // If no cookie, still respond with success (idempotent logout)
    if (!refreshToken) {
      res.status(200).json({ message: "Logged out successfully." });
      return;
    }

    // ✅ Remove refresh token from DB if present
    const admin = await Admin.findOne({ refreshToken });
    if (admin) {
      (admin as any).refreshToken = null; // If not defined in schema
      await admin.save();
    }

    const isProduction = process.env.NODE_ENV === "production";

    const cookieOptions = {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? ("none" as const) : ("lax" as const),
      path: "/", // ✅ Important for clearing cookies correctly
    };

    // ✅ Clear both tokens using same options as login
    res.clearCookie("accessToken", cookieOptions);
    res.clearCookie("refreshToken", cookieOptions);

    console.log("✅ Admin logged out successfully.");

    res.status(200).json({ message: "Logged out successfully." });
  } catch (error) {
    console.error("❌ Error logging out admin:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

export const getCurrentAdmin = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const admin = req.account as IAdmin | undefined; // Populated by protect middleware

    if (!admin) {
      res.status(401).json({ message: "Not authenticated." });
      return;
    }

    res.status(200).json({
      id: admin._id,
      name: admin.name,
      email: admin.email,
      role: admin.role,
      isSuperAdmin: admin.isSuperAdmin,
      rolePermissions: admin.rolePermissions,
      customPermissions: admin.customPermissions,
      extraPermissions: admin.extraPermissions,
      canCreateRoles: admin.canCreateRoles,
      canCreateUser: admin.canCreateUser,
      canUpdateUser: admin.canUpdateUser,
      canDeleteUser: admin.canDeleteUser,
      canGrantExtraPermissions: admin.canGrantExtraPermissions,
    });
  } catch (error) {
    console.error("❌ Error fetching current admin:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Get all users (Super Admin only)
 * @route GET /api/admin/users
 * @access Private (Super Admin only)
 */
export const getAllUsers = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account as IAdmin | undefined;

    if (!requester) {
      res.status(401).json({ message: "Unauthorized: No account found in request." });
      return;
    }

    // ✅ Only super admins can view all users
    if (!requester.isSuperAdmin) {
      console.warn(`❌ ${requester.email} attempted to view all users without super admin permission`);
      res.status(403).json({
        message: "Access denied. Only Super Admins can view all users.",
      });
      return;
    }

    const { page = 1, limit = 50, search, verified } = req.query;
    const pageNum = parseInt(page as string, 10);
    const limitNum = parseInt(limit as string, 10);
    const skip = (pageNum - 1) * limitNum;

    // Build query
    const query: any = {};
    
    if (search) {
      query.$or = [
        { name: { $regex: search as string, $options: "i" } },
        { email: { $regex: search as string, $options: "i" } },
      ];
    }

    if (verified !== undefined) {
      query.verified = verified === "true";
    }

    // Get total count
    const total = await User.countDocuments(query);

    // Get users
    const users = await User.find(query)
      .select("-password -resetPasswordToken -resetPasswordExpire -verificationToken -googleRefreshToken")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limitNum)
      .lean();

    res.status(200).json({
      users,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        pages: Math.ceil(total / limitNum),
      },
    });
  } catch (error) {
    console.error("❌ Error fetching all users:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};
