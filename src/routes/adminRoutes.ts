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
} from "../controllers/adminController.js";

import {
  requireAdmin,
  requirePermission,
  requireCreateUserPermission,
} from "../middlewares/adminMiddleware.js";

import { protect } from "../middlewares/authMiddleware.js";

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

export default router;
