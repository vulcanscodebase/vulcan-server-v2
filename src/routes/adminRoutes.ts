import express, { Router } from "express";
import type { RequestHandler } from "express";

import {
  createAdminUser,
  getAllAdmins,
  createRole,
  loginAdmin,
  setupPassword,
  logoutAdmin,
  getCurrentAdmin,
  refreshTokenAdmin,
  deleteAdmin,
  getAllUsers,
} from "../controllers/adminController.js";

import {
  superAdminMassUploadUsers,
  superAdminMassUploadPreview,
} from "../controllers/podController.js";

import {
  requireAdmin,
  requirePermission,
  requireCreateUserPermission,
} from "../middlewares/adminMiddleware.js";

import { protect } from "../middlewares/authMiddleware.js";
import { uploadExcelFile } from "../middlewares/uploadMiddleware.js";

const router: Router = express.Router();

// ✅ 1. Public Auth Routes (No Login Required)
router.post("/login", loginAdmin as RequestHandler);
router.post("/setup-password", setupPassword as RequestHandler);
router.post("/refresh-token", refreshTokenAdmin as RequestHandler);
router.post("/logout", logoutAdmin as RequestHandler);

// ✅ 2. Protected Routes (Login Required)
router.use(protect as RequestHandler);

// ✅ 3. Self Access Routes (Allow Self Modification)
router.get(
  "/me",
  requireAdmin(true) as RequestHandler,
  getCurrentAdmin as RequestHandler
);

// ✅ 4. Role Management
router.post(
  "/create-role",
  requirePermission("Roles", "create") as RequestHandler,
  createRole as RequestHandler
);

// ✅ 5. Admin User Management
router.post(
  "/create-user",
  requireCreateUserPermission as RequestHandler,
  createAdminUser as RequestHandler
);
router.get(
  "/",
  requirePermission("Team", "view") as RequestHandler,
  getAllAdmins as RequestHandler
);
router.delete(
  "/:adminId",
  requirePermission("SuperAdmin", "delete") as RequestHandler,
  deleteAdmin as RequestHandler
);

// ✅ 6. Get All Users (Super Admin Only)
router.get(
  "/users",
  requirePermission("SuperAdmin", "view") as RequestHandler,
  getAllUsers as RequestHandler
);

// ✅ 7. Super Admin Mass Upload (Super Admin Only)
router.post(
  "/mass-upload-preview",
  requireAdmin() as RequestHandler,
  uploadExcelFile as RequestHandler,
  superAdminMassUploadPreview as RequestHandler
);

router.post(
  "/mass-upload-users",
  requireAdmin() as RequestHandler,
  uploadExcelFile as RequestHandler,
  superAdminMassUploadUsers as RequestHandler
);

export default router;
