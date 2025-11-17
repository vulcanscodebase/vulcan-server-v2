import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import { Admin } from "../models/Admin.js";
import { Role } from "../models/Role.js"; // ✅ Ensure you're using the named export

dotenv.config();

export const initializeSuperAdmin = async (): Promise<void> => {
  try {
    const superAdminEmail = process.env.SUPER_ADMIN_EMAIL;
    const superAdminPassword = process.env.SUPER_ADMIN_PASSWORD;

    if (!superAdminEmail || !superAdminPassword) {
      throw new Error(
        "Missing SUPER_ADMIN_EMAIL or SUPER_ADMIN_PASSWORD in environment variables."
      );
    }

    // ✅ Check if already exists
    const existingSuperAdmin = await Admin.findOne({ email: superAdminEmail });
    if (existingSuperAdmin) {
      console.log("✅ Super Admin already exists:", existingSuperAdmin.email);
      return;
    }

    // ✅ Find or create the 'super-admin' role
    let superAdminRole = await Role.findOne({ name: "super-admin" });

    if (!superAdminRole) {
      console.log(
        "⚠️ Role 'super-admin' not found — creating one automatically..."
      );

      const SUPER_ADMIN_ID = "67fe38636b44e2a71b1a96e7";

      superAdminRole = await Role.create({
        name: "super-admin",
        defaultPermissions: [
          {
            feature: "all",
            actions: ["view", "create", "edit", "delete", "publish"],
          },
        ],
        createdBy: SUPER_ADMIN_ID, // or handle dynamically if you have a system account
      });
      console.log("✅ 'super-admin' role created.");
    }

    // ✅ Create Super Admin
    const superAdmin = await Admin.create({
      name: "Super Admin",
      email: superAdminEmail,
      password: superAdminPassword,
      isSuperAdmin: true,
      role: superAdminRole._id,
      canCreateUser: true,
      canUpdateUser: true,
      canDeleteUser: true,
      canCreateRoles: true,
      permissions: [
        {
          feature: "all",
          actions: ["view", "create", "edit", "delete", "publish"],
        },
      ],
    });

    console.log(`✅ Super Admin created successfully: ${superAdmin.email}`);
  } catch (error: any) {
    console.error("❌ Error initializing Super Admin:", error.message || error);
  }
};
