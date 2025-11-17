import express, { Router, type RequestHandler } from "express";
import { body } from "express-validator";

import {
  createPod,
  getAllPods,
  getPodById,
  getPodHierarchy,
  getPodsByParent,
  getPodUsers,
  uploadPodUsersExcel,
  processPodExcelPreview,
  bulkAddPodUsers,
  getPodInviteStatus,
  //   resendPodInvites,
  //   getInviteStatusByPod,
  removePodUser,
  addSingleUserToPod,
  //   transferPodAdmin,
  softDeletePod,
  restorePod,
  //   updatePodTags,
  //   searchPodUsers,
  //   exportPodUsersToExcel,
  //   togglePodArchiveStatus,
  //   clonePod,
  getPodAnalytics,
  //   permanentlyDeletePod,
} from "../controllers/podController.js";

import { protect } from "../middlewares/authMiddleware.js";
import {
  requireAdmin,
  requirePermission,
} from "../middlewares/adminMiddleware.js";
import { uploadExcelFile } from "../middlewares/uploadMiddleware.js"; // ✅ local version
import validateRequest from "../middlewares/validateRequest.js";

const router: Router = express.Router();

// ✅ Global Auth Protection
router.use(protect as RequestHandler);
router.use(requireAdmin() as RequestHandler);

// ✅ Pod Creation
router.post(
  "/create",
  requirePermission("Groups", "create") as RequestHandler,
  createPod as RequestHandler
);

// ✅ View Pods
router.get(
  "/all",
  requirePermission("Groups", "view") as RequestHandler,
  getAllPods as RequestHandler
);
router.get(
  "/:podId",
  requirePermission("Groups", "view") as RequestHandler,
  getPodById as RequestHandler
);

// ✅ Nested Pod Hierarchy
router.get(
  "/:podId/hierarchy",
  requirePermission("Groups", "view") as RequestHandler,
  getPodHierarchy as RequestHandler
);

// ✅ Get Pods by Parent (filter by parentPodId)
router.get(
  "/filter/by-parent/:parentPodId",
  requirePermission("Groups", "view") as RequestHandler,
  getPodsByParent as RequestHandler
);

router.get(
  "/:podId/users",
  requirePermission("Groups", "view") as RequestHandler,
  getPodUsers as RequestHandler
);

// ✅ Upload Excel & Preview (Local)
router.post(
  "/upload-users-excel/:podId",
  requirePermission("Groups", "edit") as RequestHandler,
  uploadExcelFile as RequestHandler, // ✅ Uses local multer upload
  uploadPodUsersExcel as RequestHandler
);

router.post(
  "/preview-users/:podId",
  requirePermission("Groups", "edit") as RequestHandler,
  uploadExcelFile as RequestHandler,
  processPodExcelPreview as RequestHandler
);

// ✅ Bulk Add Users
router.post(
  "/:podId/bulk-add",
  requirePermission("Groups", "edit") as RequestHandler,
  bulkAddPodUsers as RequestHandler
);

// ✅ Add Single User
router.post(
  "/:podId/add-user",
  requirePermission("Groups", "edit") as RequestHandler,
  [
    body("email").isEmail().withMessage("Valid email is required."),
    body("name").notEmpty().withMessage("Name is required."),
  ],
  validateRequest as RequestHandler,
  addSingleUserToPod as RequestHandler
);

// ✅ Remove User
router.delete(
  "/:podId/users/:userId",
  requirePermission("Groups", "edit") as RequestHandler,
  removePodUser as RequestHandler
);

// // ✅ Invite Status & Resend
router.get(
  "/:podId/invite-status",
  requirePermission("Groups", "view") as RequestHandler,
  getPodInviteStatus as RequestHandler
);

// router.get(
//   "/:podId/invite-summary",
//   requirePermission("Groups", "view") as RequestHandler,
//   getInviteStatusByPod as RequestHandler
// );

// router.post(
//   "/:podId/resend-invites",
//   requirePermission("Groups", "edit") as RequestHandler,
//   resendPodInvites as RequestHandler
// );

// // ✅ Transfer Admin
// router.put(
//   "/:podId/transfer-admin",
//   requirePermission("Groups", "edit") as RequestHandler,
//   transferPodAdmin as RequestHandler
// );

// ✅ Soft Delete / Restore / Permanent Delete
router.delete(
  "/:podId/soft-delete",
  requirePermission("Groups", "edit") as RequestHandler,
  softDeletePod as RequestHandler
);
router.patch(
  "/:podId/restore",
  requirePermission("Groups", "edit") as RequestHandler,
  restorePod as RequestHandler
);

// router.delete(
//   "/:podId/permanent-delete",
//   requirePermission("Groups", "delete") as RequestHandler,
//   permanentlyDeletePod as RequestHandler
// );

// // ✅ Update Tags
// router.put(
//   "/:podId/tags",
//   requirePermission("Groups", "edit") as RequestHandler,
//   updatePodTags as RequestHandler
// );

// // ✅ Search/Filter Users
// router.get(
//   "/:podId/users/search",
//   requirePermission("Groups", "view") as RequestHandler,
//   searchPodUsers as RequestHandler
// );

// // ✅ Export Users
// router.get(
//   "/:podId/export-users",
//   requirePermission("Groups", "view") as RequestHandler,
//   exportPodUsersToExcel as RequestHandler
// );

// // ✅ Analytics
router.get(
  "/:podId/analytics",
  requirePermission("Groups", "view") as RequestHandler,
  getPodAnalytics as RequestHandler
);

// // ✅ Archive / Unarchive
// router.patch(
//   "/:podId/archive",
//   requirePermission("Groups", "edit") as RequestHandler,
//   togglePodArchiveStatus as RequestHandler
// );

// // ✅ Clone Pod
// router.post(
//   "/:podId/clone",
//   requirePermission("Groups", "create") as RequestHandler,
//   clonePod as RequestHandler
// );

export default router;
