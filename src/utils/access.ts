import { mergePermissions } from "../middlewares/adminMiddleware.js";
import { Types } from "mongoose";
import type { IAdmin } from "../models/Admin.js";
import type { IPod } from "../models/Pod.js";

/**
 * Checks whether a requester (Admin or SuperAdmin) has access to a Pod.
 * Supports nested pod hierarchy - admins of parent pods have access to child pods.
 * @param requester - The account object (Admin)
 * @param pod - The Pod document
 * @returns boolean - true if access is granted, false otherwise
 */
export const hasPodAccess = (requester: IAdmin | any, pod: IPod): boolean => {
  if (!requester || !requester._id || !pod || !pod.createdBy) {
    console.warn("❌ hasPodAccess: Missing requester or pod.createdBy", {
      requesterExists: !!requester,
      requesterId: requester?._id,
      podExists: !!pod,
      createdBy: pod?.createdBy,
    });
    return false;
  }

  const requesterId = requester._id.toString();
  const creatorId =
    typeof pod.createdBy === "object"
      ? (pod.createdBy._id as Types.ObjectId)?.toString()
      : String(pod.createdBy);

  console.log("🔍 Checking pod access:", {
    requesterId,
    creatorId,
    isSuperAdmin: requester.isSuperAdmin,
    podId: pod._id,
    parentPodId: pod.parentPodId,
  });

  // ✅ Super Admin override
  if (requester.isSuperAdmin) {
    console.log("✅ Super Admin override");
    return true;
  }

  // ✅ Pod Creator access
  if (creatorId === requesterId) {
    console.log("✅ Pod Creator match");
    return true;
  }

  // ✅ Check if requester is the managing admin
  if (pod.managedBy && requester._id.toString() === pod.managedBy.toString()) {
    console.log("✅ Managing admin access");
    return true;
  }

  // ✅ Check if requester is admin of parent pod (nested pod inheritance)
  if (pod.parentPodId && requester._id === pod.parentPodId) {
    console.log("✅ Admin of parent pod - inherited access");
    return true;
  }

  console.warn("❌ Access denied by hasPodAccess");
  return false;
};
