import {
  type Request,
  type Response,
  type NextFunction,
  type RequestHandler,
} from "express";
import { type IAdmin } from "../models/Admin.js";
import { Types } from "mongoose";

// ✅ Merge all permission sources into a single Map
export const mergePermissions = (account: IAdmin): Map<string, Set<string>> => {
  const map = new Map<string, Set<string>>();

  const rolePermissions = account.rolePermissions || [];
  const customPermissions = account.customPermissions || [];
  const extraPermissions = account.extraPermissions || [];

  console.log(
    `🔍 Merging permissions for admin: ${account.email || "unknown email"}`
  );
  console.log("📦 rolePermissions:", rolePermissions);
  console.log("📦 customPermissions:", customPermissions);
  console.log("📦 extraPermissions:", extraPermissions);

  // Warn if role permissions missing
  if (rolePermissions.length === 0) {
    console.warn(
      "⚠️ No rolePermissions found — permission check might fail if not handled properly."
    );
  }

  // Merge all base permissions
  for (const p of [...rolePermissions, ...customPermissions]) {
    if (!map.has(p.feature)) map.set(p.feature, new Set());
    p.actions.forEach((action: string) => map.get(p.feature)?.add(action));
  }

  // Merge extra permissions (skip expired)
  const now = new Date();
  for (const p of extraPermissions) {
    if (p.expiresAt && new Date(p.expiresAt) < now && !p.isPermanent) continue;
    if (!map.has(p.feature)) map.set(p.feature, new Set());
    p.actions.forEach((action: string) => map.get(p.feature)?.add(action));
  }

  console.log(
    "✅ Final merged permission map:",
    Object.fromEntries(
      Array.from(map.entries()).map(([feature, actions]) => [
        feature,
        Array.from(actions),
      ])
    )
  );

  return map;
};

//
// ✅ 1. Basic Admin Check (and optional self-access)
//
export const requireAdmin = (allowSelf = false): RequestHandler => {
  return (req: Request, res: Response, next: NextFunction) => {
    const account = req.account as IAdmin | undefined;

    if (!account || (req.role !== "admin" && req.role !== "super-admin")) {
      return res.status(403).json({ message: "Admins only." });
    }

    if (account.isSuperAdmin) return next();
    if (
      allowSelf &&
      req.params.adminId &&
      (account._id as Types.ObjectId).toString() ===
        req.params.adminId.toString()
    ) {
      return next();
    }

    return next(); // ✅ Let permission middleware handle the rest
  };
};

//
// ✅ 2. Specific Permission Check
//
export const requirePermission = (
  feature: string,
  action: string
): RequestHandler => {
  return (req: Request, res: Response, next: NextFunction) => {
    const account = req.account as IAdmin | undefined;

    if (!account || (req.role !== "admin" && req.role !== "super-admin")) {
      return res.status(403).json({ message: "Admins only." });
    }

    if (account.isSuperAdmin) {
      console.log(`✅ Super admin override for ${account.email}`);
      return next();
    }

    const permissionsMap = mergePermissions(account);

    const hasAccess =
      (permissionsMap.has("all") && permissionsMap.get("all")?.has("full")) ||
      (permissionsMap.has(feature) && permissionsMap.get(feature)?.has(action));

    if (hasAccess) {
      console.log(
        `✅ Permission granted to ${account.email} for ${feature}:${action}`
      );
      return next();
    }

    console.warn(
      `❌ Access denied to ${account.email} for ${feature}:${action}`
    );
    return res
      .status(403)
      .json({ message: `Permission denied for ${feature}:${action}` });
  };
};

//
// ✅ 3. Role Creation Check
//
export const requireCreateUserPermission: RequestHandler = (req, res, next) => {
  const account = req.account as IAdmin | undefined;
  const { role, permissions } = req.body as {
    role: string;
    permissions: { feature: string; actions: string[] }[];
  };

  if (!account) {
    return res.status(401).json({ message: "Unauthorized: No account found." });
  }

  if (account.isSuperAdmin) return next();

  if (!account.allowedToCreateRoles?.includes(role)) {
    return res
      .status(403)
      .json({ message: "You are not allowed to create this role." });
  }

  const userPermissions = mergePermissions(account);

  const isValid = permissions.every((p) => {
    const allowedActions = userPermissions.get(p.feature) || new Set();
    return p.actions.every((action) => allowedActions.has(action));
  });

  if (!isValid) {
    return res
      .status(403)
      .json({ message: "Cannot assign permissions higher than your own." });
  }

  return next();
};

//
// ✅ 4. Super Admin Only Access
//
export const requireSuperAdmin: RequestHandler = (req, res, next) => {
  const account = req.account as IAdmin | undefined;
  if (!account || !account.isSuperAdmin) {
    return res.status(403).json({ message: "Only super admins allowed." });
  }
  return next();
};
