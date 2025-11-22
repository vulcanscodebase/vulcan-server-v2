import { Types } from "mongoose";
import type { IAdmin } from "../models/Admin.js";
import type { IUser } from "../models/User.js";
import type { IPod } from "../models/Pod.js";
import { Pod } from "../models/Pod.js";

export type RequestAccount = (IAdmin | IUser) & { isSuperAdmin?: boolean };

/**
 * Checks if a requester can access a specific user's transactions
 * - Users can only access their own transactions
 * - Admins/SuperAdmins cannot access individual user transactions directly
 * @param requester - The account object (Admin, User, or SuperAdmin)
 * @param targetUserId - The user ID whose transactions are being accessed
 * @returns boolean - true if access is granted, false otherwise
 */
export const canAccessUserTransactions = (
  requester: RequestAccount | any,
  targetUserId: string | Types.ObjectId
): boolean => {
  if (!requester || !requester._id) {
    console.warn("❌ canAccessUserTransactions: Missing requester");
    return false;
  }

  const requesterId = requester._id.toString();
  const targetId = targetUserId.toString();

  // ✅ SuperAdmin can access any user's transactions
  if (requester.isSuperAdmin) {
    console.log("✅ SuperAdmin override - can access any user transactions");
    return true;
  }

  // ✅ Users can only access their own transactions
  if (requester.role === "user" || !requester.isSuperAdmin) {
    if (requesterId === targetId) {
      console.log("✅ User can access own transactions");
      return true;
    }
    console.warn("❌ User cannot access other user's transactions");
    return false;
  }

  return false;
};

/**
 * Checks if a requester can access a pod's transactions
 * - Users: Cannot access pod transactions
 * - Admins: Can only access pods they created or manage
 * - SuperAdmins: Can access all pod transactions
 * @param requester - The account object (Admin or SuperAdmin)
 * @param pod - The Pod document
 * @returns boolean - true if access is granted, false otherwise
 */
export const canAccessPodTransactions = (
  requester: RequestAccount | any,
  pod: IPod | null
): boolean => {
  if (!requester || !requester._id) {
    console.warn("❌ canAccessPodTransactions: Missing requester");
    return false;
  }

  if (!pod) {
    console.warn("❌ canAccessPodTransactions: Pod not found");
    return false;
  }

  // ✅ Users cannot access pod transactions
  if (requester.role === "user") {
    console.warn("❌ Users cannot access pod transactions");
    return false;
  }

  const requesterId = requester._id.toString();

  // ✅ SuperAdmin can access any pod transactions
  if (requester.isSuperAdmin) {
    console.log("✅ SuperAdmin override - can access any pod transactions");
    return true;
  }

  // ✅ Admin can access pods they created
  if (pod.createdBy) {
    const creatorId =
      typeof pod.createdBy === "object"
        ? (pod.createdBy._id as Types.ObjectId)?.toString()
        : String(pod.createdBy);

    if (creatorId === requesterId) {
      console.log("✅ Admin created this pod - can access transactions");
      return true;
    }
  }

  // ✅ Admin can access pods they manage
  if (pod.managedBy && requester._id.toString() === pod.managedBy.toString()) {
    console.log("✅ Admin manages this pod - can access transactions");
    return true;
  }

  // ✅ Admin can access child pods of parent pods they manage
  if (pod.parentPodId) {
    const parentId = pod.parentPodId.toString();
    if (parentId === requesterId) {
      console.log(
        "✅ Admin manages parent pod - can access child pod transactions"
      );
      return true;
    }
  }

  console.warn("❌ Admin does not have access to this pod");
  return false;
};

/**
 * Checks if a requester can create a transaction for a specific user
 * - Users: Can only create transactions for themselves (deduction for interviews)
 * - Admins: Can create transactions for users in pods they manage
 * - SuperAdmins: Can create transactions for any user
 * @param requester - The account object (Admin, User, or SuperAdmin)
 * @param targetUserId - The user ID for whom transaction is being created
 * @param podId - The pod ID (optional, for admin transactions)
 * @returns boolean - true if access is granted, false otherwise
 */
export const canCreateTransaction = async (
  requester: RequestAccount | any,
  targetUserId: string | Types.ObjectId,
  podId?: string | Types.ObjectId
): Promise<boolean> => {
  if (!requester || !requester._id) {
    console.warn("❌ canCreateTransaction: Missing requester");
    return false;
  }

  const requesterId = requester._id.toString();
  const targetId = targetUserId.toString();

  // ✅ SuperAdmin can create transactions for anyone
  if (requester.isSuperAdmin) {
    console.log("✅ SuperAdmin override - can create any transaction");
    return true;
  }

  // ✅ User can only create deduction transactions for themselves
  if (requester.role === "user") {
    if (requesterId === targetId) {
      console.log("✅ User can create transaction for themselves");
      return true;
    }
    console.warn("❌ User cannot create transactions for others");
    return false;
  }

  // ✅ Admin creating assignment transaction for a pod member
  if (podId) {
    const pod = await Pod.findById(podId);
    if (!pod) {
      console.warn("❌ Pod not found for transaction");
      return false;
    }

    if (!canAccessPodTransactions(requester, pod)) {
      console.warn("❌ Admin cannot manage this pod");
      return false;
    }

    console.log("✅ Admin can create transaction for pod member");
    return true;
  }

  // ✅ Admin can create adjustment transactions
  console.log("✅ Admin can create adjustment transaction");
  return true;
};

/**
 * Checks if a requester can access a specific transaction
 * - Users: Can access their own transactions only
 * - Admins: Can access transactions for pods they manage
 * - SuperAdmins: Can access all transactions
 * @param requester - The account object
 * @param transaction - The transaction object with userId and podId
 * @returns boolean - true if access is granted, false otherwise
 */
export const canAccessTransaction = async (
  requester: RequestAccount | any,
  transaction: {
    userId: string | Types.ObjectId;
    podId?: string | Types.ObjectId | null;
  }
): Promise<boolean> => {
  if (!requester || !requester._id) {
    console.warn("❌ canAccessTransaction: Missing requester");
    return false;
  }

  // ✅ SuperAdmin can access any transaction
  if (requester.isSuperAdmin) {
    console.log("✅ SuperAdmin override - can access any transaction");
    return true;
  }

  // ✅ User can access their own transactions
  if (requester.role === "user") {
    if (
      requester._id.toString() === transaction.userId.toString()
    ) {
      console.log("✅ User can access their own transaction");
      return true;
    }
    console.warn("❌ User cannot access other user's transaction");
    return false;
  }

  // ✅ Admin can access transactions if they manage the associated pod
  if (transaction.podId) {
    const pod = await Pod.findById(transaction.podId);
    if (pod && canAccessPodTransactions(requester, pod)) {
      console.log("✅ Admin can access transaction for their pod");
      return true;
    }
  }

  console.warn("❌ Admin cannot access this transaction");
  return false;
};
