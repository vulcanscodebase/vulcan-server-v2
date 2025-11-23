import { type Request, type Response } from "express";
// ❌ COMMENTED OUT: fs/promises no longer needed (files parsed from memory)
// import fs from "fs/promises";
import path from "path";
import jwt from "jsonwebtoken";
import ExcelJS from "exceljs";
import validator from "validator";
import { Readable } from "stream";
import mongoose from "mongoose";

import { Pod, type IPod } from "../models/Pod.js";
import { User } from "../models/User.js";
import { Admin } from "../models/Admin.js";
import { Role } from "../models/Role.js";
import {
  sendPasswordSetupEmail,
  sendEmail,
  sendPodUserInviteEmail,
  sendPrivatePodRegistrationEmail,
} from "../utils/email.js";
import { hasPodAccess } from "../utils/access.js";
import { logPodActivity } from "../utils/podLogger.js";
import {
  recordLicenseAssignment,
  recordLicenseDeduction,
} from "../utils/transactionHelper.js";
import {
  type Profession,
  PROFESSIONS,
  type EducationStatus,
} from "../constants/enums.js";

/**
 * @desc Create a new Pod
 * @route POST /api/pods/create
 * @access Admin / SuperAdmin
 */
export const createPod = async (req: Request, res: Response): Promise<void> => {
  try {
    const creator = req.account;
    const {
      name,
      type,
      email,
      educationStatus,
      organizationName,
      instituteName,
      parentPodId,
    } = req.body;

    if (!name || !type) {
      res.status(400).json({ message: "Pod name and type are required." });
      return;
    }

    if (!["institution", "organization", "private"].includes(type)) {
      res.status(400).json({ message: "Invalid pod type." });
      return;
    }

    // Handle nested pod creation
    let parentPod = null;
    let nestingLevel = 0;
    let podPath = name;

    if (parentPodId) {
      // Validate parent pod exists
      parentPod = await Pod.findById(parentPodId);
      if (!parentPod) {
        res.status(404).json({ message: "Parent pod not found." });
        return;
      }

      // Only institution and organization pods can have children
      if (parentPod.type === "private") {
        res
          .status(400)
          .json({ message: "Private pods cannot have child pods." });
        return;
      }

      // Check if requester has access to parent pod
      if (!hasPodAccess(creator, parentPod)) {
        res.status(403).json({ message: "Access denied to parent pod." });
        return;
      }

      nestingLevel = (parentPod.nestingLevel || 0) + 1;
      podPath = `${parentPod.path || parentPod.name} > ${name}`;
    }

    const existingPod = await Pod.findOne({ name });
    if (existingPod) {
      res.status(409).json({ message: "Pod with this name already exists." });
      return;
    }

    let emailToSend = null;
    let adminName = null;

    if (type !== "private") {
      if (!email) {
        res
          .status(400)
          .json({ message: "Email is required for this pod type." });
        return;
      }
      emailToSend = email;

      if (type === "institution" && !instituteName) {
        res.status(400).json({ message: "Institute name is required." });
        return;
      }

      if (type === "organization" && !organizationName) {
        res.status(400).json({ message: "Organization name is required." });
        return;
      }

      adminName = type === "institution" ? instituteName : organizationName;
    }

    const pod = await Pod.create({
      name,
      type,
      createdBy: creator._id,
      educationStatus: educationStatus || null,
      organizationName: organizationName || null,
      instituteName: instituteName || null,
      associatedEmail: emailToSend || null,
      parentPodId: parentPodId || null,
      nestingLevel,
      path: podPath,
      childPods: [],
    });

    // Update parent pod's childPods array
    if (parentPod) {
      parentPod.childPods = parentPod.childPods || [];
      parentPod.childPods.push(pod._id as mongoose.Types.ObjectId);
      await parentPod.save();

      await logPodActivity(
        parentPod._id as mongoose.Types.ObjectId,
        "add_child_pod",
        `Child pod "${pod.name}" created.`,
        creator._id as mongoose.Types.ObjectId
      );
    }

    // Create or link admin
    if (emailToSend) {
      const desiredRoleName =
        type === "institution" ? "institution-admin" : "organization-admin";

      let roleData = await Role.findOne({ name: desiredRoleName });
      if (!roleData) {
        roleData = await Role.create({
          name: desiredRoleName,
          defaultPermissions: [
            {
              feature: "Groups",
              actions: ["view", "edit", "delete", "create", "publish"],
            },
          ],
          createdBy: creator._id,
        });
      }

      let admin = await Admin.findOne({ email: emailToSend });
      if (!admin) {
        const setupToken = jwt.sign(
          { email: emailToSend },
          process.env.JWT_SECRET!,
          {
            expiresIn: "24h",
          }
        );

        admin = await Admin.create({
          name: adminName,
          email: emailToSend,
          role: roleData._id,
          isSuperAdmin: false,
          passwordResetToken: setupToken,
          passwordResetExpires: Date.now() + 24 * 60 * 60 * 1000,
        });

        await sendPasswordSetupEmail(adminName, emailToSend, setupToken);
      } else {
        await sendEmail(
          emailToSend,
          "New Pod Created",
          `Hello ${
            admin.name || "Admin"
          },\n\nA new pod named "${name}" has been created and assigned to your account.\n\nRegards,\nVulcans Team`
        );
      }

      pod.managedBy = admin._id as mongoose.Types.ObjectId;
      await pod.save();
    }

    await logPodActivity(
      pod._id as mongoose.Types.ObjectId,
      "create",
      `Pod "${pod.name}" created.${
        parentPod ? ` (Child of ${parentPod.name})` : ""
      }`,
      creator._id as mongoose.Types.ObjectId
    );

    res.status(201).json({ message: "Pod created successfully.", pod });
  } catch (error) {
    console.error("❌ Error creating pod:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Get all Pods
 * @route GET /api/pods/all
 * @access Admin / SuperAdmin
 * @description For regular admins, returns only pods they manage/created + all child pods recursively
 *              For super admins, returns all pods
 */
export const getAllPods = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const { type, tag, includeDeleted } = req.query;

    const query: any = {};
    if (
      type &&
      ["institution", "organization", "private"].includes(type as string)
    ) {
      query.type = type;
    }

    if (tag) query.tags = tag;
    if (includeDeleted !== "true") query.isDeleted = false;

    let pods: any[] = [];

    // If not super admin, only show pods they manage or created + child pods
    if (!requester.isSuperAdmin) {
      // Get root pods where this admin is the manager or creator
      const rootPodsQuery: any = {
        $or: [
          { managedBy: requester._id },
          { createdBy: requester._id },
        ],
        isDeleted: false,
        parentPodId: null, // Only root pods
      };

      if (type && ["institution", "organization", "private"].includes(type as string)) {
        rootPodsQuery.type = type;
      }

      const rootPods = await Pod.find(rootPodsQuery)
        .populate("createdBy", "name email")
        .populate("managedBy", "name email")
        .populate("parentPodId", "name")
        .sort({ createdAt: -1 });

      // Get all child pods of root pods (recursively)
      if (rootPods.length > 0) {
        const rootPodIds = rootPods.map((p) => p._id as mongoose.Types.ObjectId);
        
        // Recursively get all child pods
        const getChildPodsRecursive = async (parentIds: mongoose.Types.ObjectId[]): Promise<any[]> => {
          if (parentIds.length === 0) return [];
          
          const childQuery: any = {
            parentPodId: { $in: parentIds },
            isDeleted: false,
          };
          if (type && ["institution", "organization", "private"].includes(type as string)) {
            childQuery.type = type;
          }

          const childPods = await Pod.find(childQuery)
            .populate("createdBy", "name email")
            .populate("managedBy", "name email")
            .populate("parentPodId", "name type")
            .sort({ createdAt: -1 });

          const childPodIds = childPods.map((p) => p._id as mongoose.Types.ObjectId);

          // Recursively get children of children
          if (childPods.length > 0) {
            const nestedChildren = await getChildPodsRecursive(childPodIds);
            return [...childPods, ...nestedChildren];
          }

          return childPods;
        };

        const childPods = await getChildPodsRecursive(rootPodIds);
        pods = [...rootPods, ...childPods];
      }
    } else {
      // Super admin sees all pods
      pods = await Pod.find(query)
        .populate("createdBy", "name email")
        .populate("managedBy", "name email")
        .populate("parentPodId", "name")
        .sort({ createdAt: -1 });
    }

    res.status(200).json({ pods });
  } catch (error) {
    console.error("❌ Error fetching pods:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Get Pod by ID
 */
export const getPodById = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId } = req.params;
    const requester = req.account;

    const pod = await Pod.findById(podId)
      .populate("invitedUsers.userId", "name email verified")
      .populate("createdBy", "name email");

    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    if (!hasPodAccess(requester, pod)) {
      res.status(403).json({ message: "Access denied." });
      return;
    }

    res.status(200).json({ pod });
  } catch (error) {
    console.error("❌ Error fetching pod:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Get Pod Hierarchy (parent and children)
 * @route GET /api/pods/:podId/hierarchy
 * @access Admin / SuperAdmin
 */
export const getPodHierarchy = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId } = req.params;
    const requester = req.account;

    const pod = await Pod.findById(podId)
      .populate("parentPodId", "name type nestingLevel path")
      .populate("childPods", "name type nestingLevel path");

    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    if (!hasPodAccess(requester, pod)) {
      res.status(403).json({ message: "Access denied." });
      return;
    }

    res.status(200).json({
      pod: {
        _id: pod._id,
        name: pod.name,
        type: pod.type,
        nestingLevel: pod.nestingLevel,
        path: pod.path,
      },
      parent: pod.parentPodId || null,
      children: pod.childPods || [],
    });
  } catch (error) {
    console.error("❌ Error fetching pod hierarchy:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Get all Pods with optional parent filter
 * @route GET /api/pods/all
 * @access Admin / SuperAdmin
 */
export const getPodsByParent = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const { parentPodId } = req.query;

    const query: any = {};
    if (parentPodId) {
      query.parentPodId = parentPodId;
    } else {
      // Get only root pods (no parent)
      query.parentPodId = null;
    }

    const pods = await Pod.find(query)
      .populate("createdBy", "name email")
      .sort({ createdAt: -1 });

    res.status(200).json({ pods });
  } catch (error) {
    console.error("❌ Error fetching pods by parent:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Get all users in a specific Pod
 * @route GET /api/pods/:podId/users
 * @access Private (Super Admin or Pod Creator)
 */

export const getPodUsers = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId } = req.params;
    const requester = req.account;
    const { page = 1, limit = 10, search = "" } = req.query;

    let pod = await Pod.findById(podId)
      .populate("createdBy", "email") // May resolve to null if admin doesn't exist
      .populate("invitedUsers.userId", "email verified");

    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    // ✅ Auto-fix orphaned createdBy
    if (!pod.createdBy) {
      console.warn(
        `⚠️ Pod ${pod.name} has orphaned createdBy. Attempting auto-reassignment.`
      );

      const superAdmin = await Admin.findOne({ isSuperAdmin: true });
      if (superAdmin) {
        pod.createdBy = superAdmin._id as mongoose.Types.ObjectId;
        await pod.save();
        console.log(
          `✅ Pod ${pod.name} reassigned to Super Admin: ${superAdmin.email}`
        );
      } else {
        console.error("❌ No super admin found to reassign pod ownership.");
      }

      // Re-fetch with populated admin now
      pod = await Pod.findById(podId)
        .populate("createdBy", "email")
        .populate("invitedUsers.userId", "email verified");
    }

    if (!hasPodAccess(requester, pod!)) {
      res.status(403).json({
        message: "You do not have permission to view this pod's users.",
      });
      return;
    }

    const pageNum = parseInt(String(page)) || 1;
    const limitNum = parseInt(String(limit)) || 10;
    const skip = (pageNum - 1) * limitNum;

    const podUserIds = (pod?.invitedUsers || [])
      .map((invite) => invite.userId?._id || invite.userId)
      .filter((id) => !!id);

    const query: any = { _id: { $in: podUserIds } };
    const searchStr = String(search || "");
    if (searchStr.trim()) {
      query.$or = [
        { name: { $regex: searchStr, $options: "i" } },
        { email: { $regex: searchStr, $options: "i" } },
      ];
    }

    const [total, users] = await Promise.all([
      User.countDocuments(query),
      User.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limitNum)
        .select(
          "name email verified profileLocked profession schoolOrCollege organization qualification dob createdAt"
        ),
    ]);

    const usersWithStatus = users.map((user) => {
      const invite = pod!.invitedUsers.find(
        (i) => i.userId?.toString() === String(user._id).toString()
      );
      const status = user.verified ? "joined" : invite ? "pending" : "unknown";

      return {
        ...user.toObject(),
        status,
      };
    });

    res.status(200).json({
      podId: pod!._id,
      podName: pod!.name,
      totalUsers: total,
      currentPage: pageNum,
      totalPages: Math.ceil(total / limitNum),
      users: usersWithStatus,
    });
  } catch (error) {
    console.error("❌ Error fetching paginated pod users:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Upload Excel of Pod Users (Parse from memory, NO storage)
 */
export const uploadPodUsersExcel = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId } = req.params;
    const requester = req.account;

    console.log(req, req.params, req.file);

    if (!req.file?.buffer) {
      res.status(400).json({ message: "Excel file is required." });
      return;
    }

    const pod = await Pod.findById(podId);
    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    if (!hasPodAccess(requester, pod)) {
      res.status(403).json({ message: "Unauthorized." });
      return;
    }

    // ✅ Parse directly from buffer (in memory, no file storage)
    const ext = path.extname(req.file.originalname).toLowerCase();
    const workbook = new ExcelJS.Workbook();
    const stream = Readable.from(req.file.buffer as any);
    const worksheet =
      ext === ".csv"
        ? await workbook.csv.read(stream)
        : (await workbook.xlsx.load(req.file.buffer as any)).worksheets[0];

    const extractCellValue = (cell: any): string =>
      typeof cell?.value === "object" && cell.value?.text
        ? cell.value.text.trim()
        : cell?.value?.toString().trim() || "";

    const rows: any[] = [];
    worksheet?.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return;
      const name = extractCellValue(row.getCell("A"));
      const uniqueId = extractCellValue(row.getCell("B"));
      const email = extractCellValue(row.getCell("C")).toLowerCase();
      const licensesRaw = row.getCell("D").value;
      const licenses =
        typeof licensesRaw === "number"
          ? licensesRaw
          : typeof licensesRaw === "string"
          ? parseInt(licensesRaw, 10) || 0
          : 0;
      if (email) rows.push({ name, uniqueId, email, licenses });
    });

    const newUsers: any[] = [];
    const existingUsers: any[] = [];
    const invalidEmails: string[] = [];

    for (const row of rows) {
      const { email } = row;
      if (!validator.isEmail(email)) {
        invalidEmails.push(email);
        continue;
      }

      const exists = await User.findOne({ email });
      const baseUser = {
        email,
        name: pod.type !== "private" ? row.name : undefined,
        uniqueId: row.uniqueId || null,
        licenses: row.licenses || 0,
      };

      exists ? existingUsers.push(baseUser) : newUsers.push(baseUser);
    }

    // ❌ COMMENTED OUT: File storage removed
    // Previously: filePath: req.file.path
    // Now: File is only in memory, not stored anywhere

    res.status(200).json({
      message: "Excel processed successfully.",
      newUsers,
      existingUsers,
      invalidEmails,
      // ❌ filePath removed - file not stored
    });
  } catch (error) {
    console.error("❌ Error processing Excel:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Preview Excel Data Before Adding Users (Parse from memory, NO storage)
 */
export const processPodExcelPreview = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId } = req.params;
    const requester = req.account;

    if (!req.file?.buffer) {
      res.status(400).json({ message: "No file uploaded." });
      return;
    }

    const pod = await Pod.findById(podId);
    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    if (!hasPodAccess(requester, pod)) {
      res.status(403).json({ message: "Unauthorized." });
      return;
    }

    // ✅ Parse directly from buffer (in memory, no file storage)
    const ext = path.extname(req.file.originalname).toLowerCase();
    const workbook = new ExcelJS.Workbook();
    const stream = Readable.from(req.file.buffer as any);
    const worksheet =
      ext === ".csv"
        ? await workbook.csv.read(stream)
        : (await workbook.xlsx.load(req.file.buffer as any)).worksheets[0];

    const extractCellValue = (cell: any): string =>
      typeof cell?.value === "object" && cell.value?.text
        ? cell.value.text.trim()
        : cell?.value?.toString().trim() || "";

    const rows: any[] = [];
    worksheet?.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return;
      const name = extractCellValue(row.getCell("A"));
      const uniqueId = extractCellValue(row.getCell("B"));
      const email = extractCellValue(row.getCell("C")).toLowerCase();
      const licensesRaw = row.getCell("D").value;
      const licenses =
        typeof licensesRaw === "number"
          ? licensesRaw
          : typeof licensesRaw === "string"
          ? parseInt(licensesRaw, 10) || 0
          : 0;
      if (email) rows.push({ name, uniqueId, email, licenses });
    });

    const validEmails = rows
      .map((r) => r.email)
      .filter((e) => validator.isEmail(e));
    const existingUsers = await User.find({ email: { $in: validEmails } });
    const existingSet = new Set(existingUsers.map((u) => u.email));

    const newUsers = rows.filter((r) => !existingSet.has(r.email));
    const invalidEmails = rows
      .map((r) => r.email)
      .filter((e) => !validator.isEmail(e));

    res.status(200).json({
      summary: {
        total: rows.length,
        newUsers,
        existingUsers,
        invalidEmails,
      },
    });
  } catch (error) {
    console.error("❌ Error previewing Excel:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Bulk Add Users to Pod
 * @route POST /api/pods/:podId/bulk-add
 * @access Admin / SuperAdmin
 */
export const bulkAddPodUsers = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId } = req.params;
    const { newUsers = [], existingUsers = [] } = req.body;
    const admin = req.account;

    const pod = await Pod.findById(podId);
    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    if (!hasPodAccess(admin, pod)) {
      res
        .status(403)
        .json({ message: "You do not have permission to modify this pod." });
      return;
    }

    const isLocked = pod.type !== "private";

    const invitedUserRecords = await Promise.all(
      newUsers.map(async (user: any) => {
        const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET!, {
          expiresIn: "2d",
        });

        const profession: Profession =
          pod.type === "institution" ? "Student" : "IT Profession";

        const newUser = new User({
          email: user.email,
          name: pod.type === "private" ? "Pending Registration" : user.name,
          qualification:
            pod.type !== "private" ? user.qualification : undefined,
          dob:
            pod.type !== "private" && user.dob ? new Date(user.dob) : undefined,
          uniqueId: user.uniqueId || null,
          licenses: user.licenses || 0,
          profession,
          schoolOrCollege:
            pod.type === "institution" ? pod.institutionName : undefined,
          organization:
            pod.type === "organization" ? pod.organizationName : undefined,
          educationStatus: pod.educationStatus || null,
          verificationToken: token,
          verified: false,
          profileLocked: isLocked,
        });

        await newUser.save();

        // Record license assignment transaction for new user
        if (user.licenses && user.licenses > 0) {
          await recordLicenseAssignment(
            newUser._id as mongoose.Types.ObjectId,
            user.licenses,
            pod._id as mongoose.Types.ObjectId,
            admin._id as mongoose.Types.ObjectId,
            "Bulk Assignment",
            `Licenses assigned during bulk pod user creation for pod "${pod.name}"`
          );
        }

        if (pod.type === "private") {
          await sendPrivatePodRegistrationEmail(user.email, token, pod.name);
        } else {
          await sendPodUserInviteEmail(user.email, token, pod.name);
        }

        pod.invitedUsers.push({
          email: user.email,
          userId: newUser._id as mongoose.Types.ObjectId,
          status: "pending",
        });

        return newUser;
      })
    );

    const updatedUsers = await Promise.all(
      existingUsers.map(async (user: any) => {
        const existing = await User.findOne({ email: user.email });
        if (!existing) return null;

        const previousLicenses = existing.licenses || 0;

        if (pod.type !== "private") {
          const profession: Profession =
            pod.type === "institution" ? "Student" : "IT Profession";
          existing.profession = profession;
          existing.schoolOrCollege =
            pod.institutionName || existing.schoolOrCollege || null;
          existing.organization =
            pod.organizationName || existing.organization || null;
          if (pod.educationStatus) {
            existing.educationStatus = pod.educationStatus;
          }
          existing.profileLocked = true;
        }

        if (user.uniqueId) {
          existing.uniqueId = user.uniqueId;
        }

        if (user.licenses) {
          existing.licenses = user.licenses;
        }

        await existing.save();

        // Record license assignment transaction if licenses changed
        if (user.licenses && user.licenses > previousLicenses) {
          const licensesDifference = user.licenses - previousLicenses;
          await recordLicenseAssignment(
            existing._id as mongoose.Types.ObjectId,
            licensesDifference,
            pod._id as mongoose.Types.ObjectId,
            admin._id as mongoose.Types.ObjectId,
            "Bulk Assignment",
            `Licenses assigned during bulk pod user update for pod "${pod.name}"`
          );
        }

        const alreadyInvited = pod.invitedUsers.find(
          (i) => i.email === user.email
        );
        if (!alreadyInvited) {
          pod.invitedUsers.push({
            email: user.email,
            userId: existing._id as mongoose.Types.ObjectId,
            status: existing.verified ? "joined" : "pending",
          });
        }

        await sendEmail(
          user.email,
          "You've been added to a new pod",
          `Hello,\n\nYou've been added to the pod "${pod.name}". Please log in to your account to continue.\n\nThank you.`
        );

        return existing;
      })
    );

    await pod.save();

    const addedCount = invitedUserRecords.length;
    const updatedCount = updatedUsers.filter(Boolean).length;

    await logPodActivity(
      pod._id as mongoose.Types.ObjectId,
      "bulk-add-users",
      `Bulk added ${addedCount} new and ${updatedCount} existing users.`,
      admin._id as mongoose.Types.ObjectId
    );

    res.status(200).json({
      message: "Bulk user upload complete.",
      podId,
      addedUsers: addedCount,
      updatedUsers: updatedCount,
    });
  } catch (error) {
    console.error("❌ Error in bulkAddPodUsers:", error);
    res.status(500).json({
      message: "Internal server error during bulk user addition.",
    });
  }
};

export const addSingleUserToPod = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId } = req.params;
    const { name, email, qualification, dob, uniqueId, licenses } = req.body;
    const requester = req.account;

    if (!email || !validator.isEmail(email)) {
      res.status(400).json({ message: "Valid email is required." });
      return;
    }

    const pod = await Pod.findById(podId);
    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    if (!hasPodAccess(requester, pod)) {
      res
        .status(403)
        .json({ message: "You do not have permission to modify this pod." });
      return;
    }

    let user = await User.findOne({ email: email.toLowerCase() });
    const profileLocked = pod.type !== "private";
    const token = jwt.sign({ email }, process.env.JWT_SECRET!, {
      expiresIn: "2d",
    });
    const isNewUser = !user;

    // ✅ License validation - Check if pod has enough available licenses
    // Super admins bypass this check
    if (licenses && licenses > 0 && !requester.isSuperAdmin) {
      const podTotal = pod.totalLicenses || 0;
      const podAssigned = pod.assignedLicenses || 0;
      const podAvailable = Math.max(0, podTotal - podAssigned);
      
      const previousUserLicenses = user?.licenses || 0;
      const licensesToAssign = isNewUser ? licenses : Math.max(0, licenses - previousUserLicenses);
      
      if (licensesToAssign > podAvailable) {
        res.status(400).json({
          message: `Insufficient licenses in pod. Available: ${podAvailable}, Requested: ${licensesToAssign}.`,
          pod: {
            name: pod.name,
            totalLicenses: podTotal,
            assignedLicenses: podAssigned,
            availableLicenses: podAvailable,
          },
        });
        return;
      }
    }

    const profession =
      pod.type === "institution"
        ? "Student"
        : pod.type === "organization"
        ? "IT Profession" // ✅ fixed enum value
        : undefined;

    const userDetails = {
      email: email.toLowerCase(),
      name: pod.type === "private" ? "Pending Registration" : name,
      qualification: pod.type !== "private" ? qualification : undefined,
      dob: pod.type !== "private" && dob ? new Date(dob) : undefined,
      uniqueId: uniqueId || null,
      licenses: licenses || 0,
      profession,
      schoolOrCollege:
        pod.type === "institution" ? pod.institutionName : undefined,
      organization:
        pod.type === "organization" ? pod.organizationName : undefined,
      educationStatus: pod.educationStatus || null,
      profileLocked,
    };

    if (isNewUser) {
      user = new User({
        ...userDetails,
        verificationToken: token,
        verified: false,
      });

      await user.save();

      // Record license assignment transaction for new user
      if (licenses && licenses > 0) {
        await recordLicenseAssignment(
          user._id as mongoose.Types.ObjectId,
          licenses,
          pod._id as mongoose.Types.ObjectId,
          requester._id as mongoose.Types.ObjectId,
          "Pod Assignment",
          `Licenses assigned during pod user creation for pod "${pod.name}"`
        );
        
        // Update pod's assigned licenses count
        pod.assignedLicenses = (pod.assignedLicenses || 0) + licenses;
      }

      if (pod.type === "private") {
        await sendPrivatePodRegistrationEmail(email, token, pod.name);
      } else {
        await sendPodUserInviteEmail(email, token, pod.name);
      }

      pod.invitedUsers = pod.invitedUsers || [];
      pod.invitedUsers.push({
        email,
        userId: user._id as mongoose.Types.ObjectId,
        status: "pending",
      });
    } else {
      const previousLicenses = user?.licenses || 0;

      if (profileLocked && user) {
        Object.assign(user, userDetails);
        await user.save();
      } else if (user && licenses) {
        // Update licenses even for private pods
        user.licenses = licenses;
        if (uniqueId) {
          user.uniqueId = uniqueId;
        }
        await user.save();
      }

      // Record license assignment transaction if licenses changed
      if (user && licenses && licenses > previousLicenses) {
        const licensesDifference = licenses - previousLicenses;
        await recordLicenseAssignment(
          user._id as mongoose.Types.ObjectId,
          licensesDifference,
          pod._id as mongoose.Types.ObjectId,
          requester._id as mongoose.Types.ObjectId,
          "Pod Assignment",
          `Licenses assigned during pod user update for pod "${pod.name}"`
        );
        
        // Update pod's assigned licenses count
        pod.assignedLicenses = (pod.assignedLicenses || 0) + licensesDifference;
      }

      const alreadyInvited = pod.invitedUsers?.find((i) => i.email === email);
      if (!alreadyInvited && user) {
        pod.invitedUsers = pod.invitedUsers || [];
        pod.invitedUsers.push({
          email,
          userId: user._id as mongoose.Types.ObjectId,
          status: user.verified ? "joined" : "pending",
        });
      }

      await sendEmail(
        email,
        "You've been added to a new pod",
        `Hello,\n\nYou've been added to the pod "${pod.name}". Please log in to your account to continue.\n\nThank you.`
      );
    }

    await pod.save();

    await logPodActivity(
      pod._id as mongoose.Types.ObjectId,
      "add-user",
      `User ${email} added to pod.`,
      requester._id as mongoose.Types.ObjectId,
      true
    );

    res.status(200).json({
      message: `✅ User ${email} added to pod successfully.`,
      podId: pod._id,
      userId: user?._id,
    });
  } catch (error) {
    console.error("❌ Error adding single user to pod:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Remove a user from a Pod
 * @route DELETE /api/pods/:podId/users/:userId
 * @access Private (Super Admin or Pod Creator)
 */
export const removePodUser = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId, userId } = req.params;
    const licenseRefund = req.body?.licenseRefund; // Optional: number of licenses to refund
    const requester = req.account;

    console.log(
      `🗑️ ${requester.email} is trying to remove user ${userId} from pod ${podId}`
    );

    const pod = await Pod.findById(podId);
    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    // ✅ Centralized access control
    if (!hasPodAccess(requester, pod)) {
      res
        .status(403)
        .json({ message: "You do not have permission to modify this pod." });
      return;
    }

    const user = await User.findById(userId);

    // ✅ Remove user from invitedUsers array (if present)
    pod.invitedUsers = (pod.invitedUsers || []).filter(
      (inv) => inv.userId?.toString() !== userId
    );

    await pod.save();

    // ✅ Unlock profile if applicable
    if (pod.type !== "private" && user) {
      user.profileLocked = false;
      await user.save();
    }

    // ✅ Record license deduction transaction if specified
    if (user && licenseRefund && licenseRefund > 0) {
      await recordLicenseDeduction(
        user._id as mongoose.Types.ObjectId,
        licenseRefund,
        requester._id as mongoose.Types.ObjectId,
        "Refund",
        `Licenses refunded due to removal from pod "${pod.name}"`
      );
    }

    // ✅ Activity Log
    await logPodActivity(
      pod._id as mongoose.Types.ObjectId,
      "remove-user",
      `User ${user?.email || userId} removed from pod "${pod.name}"${
        licenseRefund ? ` with license refund of ${licenseRefund}` : ""
      }`,
      requester._id as mongoose.Types.ObjectId,
      true
    );

    console.log(`✅ User ${userId} removed from pod ${pod.name}`);
    res.status(200).json({
      message: "User removed from pod successfully.",
      podId: pod._id,
      removedUserId: userId,
      licenseRefundRecorded: licenseRefund ? true : false,
    });
  } catch (error) {
    console.error("❌ Error removing user from pod:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Soft Delete a Pod
 * @route DELETE /api/pods/:podId
 * @access Private (Super Admin or Pod Creator)
 * @description Soft deletes the pod and recursively soft deletes all child pods
 */
export const softDeletePod = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId } = req.params;
    const requester = req.account;

    console.log(
      `🗑️ ${requester.email} is attempting to soft delete pod: ${podId}`
    );

    const pod = await Pod.findById(podId);
    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    // ✅ Centralized permission check
    if (!hasPodAccess(requester, pod)) {
      res
        .status(403)
        .json({ message: "You do not have permission to delete this pod." });
      return;
    }

    if (pod.isDeleted) {
      res.status(400).json({ message: "Pod is already marked as deleted." });
      return;
    }

    // Recursively find and soft delete all child pods
    const softDeleteChildPodsRecursive = async (
      parentId: mongoose.Types.ObjectId
    ): Promise<number> => {
      // Find all direct child pods that are not already deleted
      const childPods = await Pod.find({
        parentPodId: parentId,
        isDeleted: false,
      });

      let deletedCount = 0;

      // Soft delete each child pod
      for (const childPod of childPods) {
        childPod.isDeleted = true;
        childPod.deletedAt = new Date();
        await childPod.save();

        // Recursively delete children of this child
        const nestedCount = await softDeleteChildPodsRecursive(
          childPod._id as mongoose.Types.ObjectId
        );

        deletedCount += 1 + nestedCount; // Count this child + its children

        await logPodActivity(
          childPod._id as mongoose.Types.ObjectId,
          "soft-delete",
          `Child pod was soft-deleted along with parent pod "${pod.name}" by ${requester.email}`,
          requester._id as mongoose.Types.ObjectId
        );
      }

      return deletedCount;
    };

    // Soft delete the parent pod
    pod.isDeleted = true;
    pod.deletedAt = new Date();
    await pod.save();

    // Recursively soft delete all child pods
    const childPodsDeletedCount = await softDeleteChildPodsRecursive(
      pod._id as mongoose.Types.ObjectId
    );

    console.log(
      `✅ Pod '${pod.name}' soft deleted along with ${childPodsDeletedCount} child pod(s).`
    );

    await logPodActivity(
      pod._id as mongoose.Types.ObjectId,
      "soft-delete",
      `Pod was soft-deleted by ${requester.email}${childPodsDeletedCount > 0 ? ` along with ${childPodsDeletedCount} child pod(s)` : ""}`,
      requester._id as mongoose.Types.ObjectId
    );

    res.status(200).json({
      message: `Pod has been soft deleted${childPodsDeletedCount > 0 ? ` along with ${childPodsDeletedCount} child pod(s)` : ""}.`,
      deletedChildPodsCount: childPodsDeletedCount,
    });
  } catch (error) {
    console.error("❌ Error during soft delete:", error);
    res
      .status(500)
      .json({ message: "Internal server error during soft delete." });
  }
};

/**
 * @desc Get Pod Invite Status Summary
 * @route GET /api/pods/:podId/invite-status
 * @access Private (Super Admin or Pod Creator)
 */
export const getPodInviteStatus = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId } = req.params;
    const requester = req.account;

    console.log(
      `🔍 ${requester.email} is checking invite status for Pod ID: ${podId}`
    );

    const pod = await Pod.findById(podId).populate(
      "invitedUsers.userId",
      "email name verified"
    );
    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    // ✅ Centralized permission check
    if (!hasPodAccess(requester, pod)) {
      res.status(403).json({
        message: "You do not have access to this Pod's invite status.",
      });
      return;
    }

    // ✅ Prepare summary
    const summary: any = {
      podId: pod._id,
      podName: pod.name,
      total: pod.invitedUsers.length,
      completed: 0,
      pending: 0,
      users: [],
    };

    for (const invite of pod.invitedUsers) {
      const user = invite.userId as any;
      const isVerified = user?.verified || false;
      const status = isVerified ? "joined" : "pending";

      if (status === "joined") summary.completed++;
      else summary.pending++;

      summary.users.push({
        name: user?.name || null,
        email: invite.email,
        verified: isVerified,
        status,
      });
    }

    console.log(`✅ Invite status for pod '${pod.name}' prepared.`);
    res.status(200).json(summary);
  } catch (error) {
    console.error("❌ Error fetching pod invite status:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Restore a Soft-Deleted Pod
 * @route PATCH /api/pods/:podId/restore
 * @access Private (Super Admin or Pod Creator)
 */
export const restorePod = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId } = req.params;
    const requester = req.account;

    const pod = await Pod.findById(podId);
    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    if (!pod.isDeleted) {
      res.status(400).json({ message: "Pod is not marked as deleted." });
      return;
    }

    // ✅ Centralized access check
    if (!hasPodAccess(requester, pod)) {
      res
        .status(403)
        .json({ message: "You do not have permission to restore this pod." });
      return;
    }

    // Check if this is a child pod and if its parent is still deleted
    if (pod.parentPodId) {
      const parentPod = await Pod.findById(pod.parentPodId);
      if (parentPod && parentPod.isDeleted) {
        res.status(400).json({
          message: `Cannot restore child pod. Parent pod "${parentPod.name}" is still in the bin. Please restore the parent pod first.`,
        });
        return;
      }
    }

    pod.isDeleted = false;
    pod.deletedAt = null;
    await pod.save();

    await logPodActivity(
      pod._id as mongoose.Types.ObjectId,
      "restore",
      `Pod restored by ${requester.email}`,
      requester._id as mongoose.Types.ObjectId,
      true
    );

    res.status(200).json({ message: "✅ Pod restored successfully." });
  } catch (error) {
    console.error("❌ Error restoring pod:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Permanently Delete a Pod (Hard Delete)
 * @route DELETE /api/pods/:podId/permanent-delete
 * @access Private (Super Admin only)
 * @description Permanently removes the pod from the database. This action cannot be undone.
 */
export const permanentlyDeletePod = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId } = req.params;
    const requester = req.account;

    console.log(
      `🗑️ ${requester.email} is attempting to permanently delete pod: ${podId}`
    );

    // Only super admins can permanently delete pods
    if (!requester.isSuperAdmin) {
      res.status(403).json({
        message: "Only super admins can permanently delete pods.",
      });
      return;
    }

    const pod = await Pod.findById(podId);
    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    // Check if pod has child pods
    const childPods = await Pod.find({ parentPodId: podId, isDeleted: false });
    if (childPods.length > 0) {
      res.status(400).json({
        message: `Cannot permanently delete pod. It has ${childPods.length} active child pod(s). Please delete or move child pods first.`,
      });
      return;
    }

    // Log the deletion before actually deleting
    await logPodActivity(
      pod._id as mongoose.Types.ObjectId,
      "permanent-delete",
      `Pod permanently deleted by ${requester.email}. Pod name: ${pod.name}`,
      requester._id as mongoose.Types.ObjectId
    );

    // Permanently delete the pod
    await Pod.findByIdAndDelete(podId);

    console.log(`✅ Pod '${pod.name}' permanently deleted.`);

    res.status(200).json({
      message: "Pod has been permanently deleted.",
      deletedPodId: podId,
    });
  } catch (error) {
    console.error("❌ Error during permanent delete:", error);
    res.status(500).json({
      message: "Internal server error during permanent delete.",
    });
  }
};

/**
 * @desc Get Pod Analytics Summary
 * @route GET /api/pods/:podId/analytics
 * @access Private (Super Admin or Pod Creator)
 */
export const getPodAnalytics = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId } = req.params;
    const requester = req.account;

    const pod = await Pod.findById(podId).populate(
      "invitedUsers.userId",
      "verified profileLocked profession"
    );

    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    // ✅ Permission check using utility
    if (!hasPodAccess(requester, pod)) {
      res.status(403).json({
        message:
          "Access denied. You are not authorized to view this pod's analytics.",
      });
      return;
    }

    const userIds = (
      pod.invitedUsers.map((invite) => invite.userId) as any[]
    ).filter(Boolean);

    const totalUsers = userIds.length;
    const verifiedUsers = userIds.filter((user) => user.verified).length;
    const profileLockedCount = userIds.filter(
      (user) => user.profileLocked
    ).length;

    const institutionUsers = userIds.filter(
      (user) => user.profession === "Student"
    ).length;
    const organizationUsers = userIds.filter(
      (user) => user.profession === "IT Professional"
    ).length;
    const privateUsers = totalUsers - institutionUsers - organizationUsers;

    res.status(200).json({
      podId: pod._id,
      podName: pod.name,
      totalUsers,
      verifiedUsers,
      pendingUsers: totalUsers - verifiedUsers,
      profileLockedCount,
      institutionUsers,
      organizationUsers,
      privateUsers,
    });
  } catch (error) {
    console.error("❌ Error fetching pod analytics:", error);
    res.status(500).json({
      message: "Internal server error while fetching analytics.",
    });
  }
};

/**
 * @desc Assign or add licenses to a pod (Super Admin only)
 * @route POST /api/pods/:podId/assign-licenses
 * @access Private (Super Admin only)
 */
export const assignLicensesToPod = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const { podId } = req.params;
    const { licenses, operation } = req.body; // operation: "set" or "add"

    // Super Admin check
    if (!requester.isSuperAdmin) {
      res.status(403).json({
        message: "Access denied. Only Super Admin can assign licenses to pods.",
      });
      return;
    }

    // Validate licenses
    if (typeof licenses !== "number" || licenses < 0) {
      res.status(400).json({
        message: "Licenses must be a positive number.",
      });
      return;
    }

    // Validate operation
    if (operation && !["set", "add"].includes(operation)) {
      res.status(400).json({
        message: 'Operation must be either "set" or "add".',
      });
      return;
    }

    const pod = await Pod.findById(podId);
    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    const previousTotal = pod.totalLicenses || 0;
    const previousAssigned = pod.assignedLicenses || 0;
    const previousAvailable = Math.max(0, previousTotal - previousAssigned);

    let newTotal: number;
    let operationType: string;

    if (operation === "add") {
      // Add more licenses to existing pool
      newTotal = previousTotal + licenses;
      operationType = "added";
    } else {
      // Set total licenses (default behavior)
      newTotal = licenses;
      operationType = "set";
    }

    // Ensure total licenses is not less than already assigned licenses
    if (newTotal < previousAssigned) {
      res.status(400).json({
        message: `Cannot set total licenses to ${newTotal}. ${previousAssigned} licenses are already assigned to users. Total must be at least ${previousAssigned}.`,
        currentAssigned: previousAssigned,
      });
      return;
    }

    pod.totalLicenses = newTotal;
    await pod.save();

    const newAvailable = Math.max(0, newTotal - previousAssigned);

    await logPodActivity(
      pod._id as mongoose.Types.ObjectId,
      "license-assignment",
      `Licenses ${operationType}: ${licenses} (Total: ${previousTotal} → ${newTotal}, Available: ${previousAvailable} → ${newAvailable})`,
      requester._id as mongoose.Types.ObjectId,
      true
    );

    res.status(200).json({
      message: `✅ Successfully ${operationType} ${licenses} licenses to pod "${pod.name}".`,
      pod: {
        _id: pod._id,
        name: pod.name,
        licenses: {
          total: newTotal,
          assigned: previousAssigned,
          available: newAvailable,
          previousTotal,
          previousAvailable,
          licenseChange: newTotal - previousTotal,
        },
      },
    });
  } catch (error) {
    console.error("❌ Error assigning licenses to pod:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Get pod license information
 * @route GET /api/pods/:podId/licenses
 * @access Private (Admin/Super Admin)
 */
export const getPodLicenses = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const { podId } = req.params;

    const pod = await Pod.findById(podId);
    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    // Permission check
    if (!hasPodAccess(requester, pod)) {
      res.status(403).json({
        message: "Access denied. You are not authorized to view this pod's licenses.",
      });
      return;
    }

    const total = pod.totalLicenses || 0;
    const assigned = pod.assignedLicenses || 0;
    const available = Math.max(0, total - assigned);
    const usagePercentage = total > 0 ? Math.round((assigned / total) * 100) : 0;

    res.status(200).json({
      message: "Pod license information retrieved successfully.",
      pod: {
        _id: pod._id,
        name: pod.name,
        type: pod.type,
      },
      licenses: {
        total,
        assigned,
        available,
        usagePercentage,
        canAssignMore: available > 0,
      },
    });
  } catch (error) {
    console.error("❌ Error fetching pod licenses:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Set or update total licenses for a pod (Super Admin only)
 * @route PUT /api/pods/:podId/licenses/set
 * @access Super Admin only
 */
export const setPodLicenses = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId } = req.params;
    const { totalLicenses } = req.body;
    const requester = req.account;

    // Only super admin can set pod licenses
    if (!requester.isSuperAdmin) {
      res.status(403).json({
        message: "Access denied. Only super admins can set pod licenses.",
      });
      return;
    }

    if (typeof totalLicenses !== "number" || totalLicenses < 0) {
      res.status(400).json({
        message: "Valid totalLicenses (non-negative number) is required.",
      });
      return;
    }

    const pod = await Pod.findById(podId);
    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    const previousTotal = pod.totalLicenses || 0;
    const assigned = pod.assignedLicenses || 0;

    // Warn if setting total below already assigned (but allow it)
    if (totalLicenses < assigned) {
      console.warn(
        `⚠️  Setting total licenses (${totalLicenses}) below assigned licenses (${assigned}) for pod ${pod.name}`
      );
    }

    pod.totalLicenses = totalLicenses;
    await pod.save();

    await logPodActivity(
      pod._id as mongoose.Types.ObjectId,
      "set-licenses",
      `Total licenses set to ${totalLicenses} (was ${previousTotal})`,
      requester._id as mongoose.Types.ObjectId,
      true
    );

    const available = Math.max(0, totalLicenses - assigned);

    res.status(200).json({
      message: `✅ Pod licenses set successfully to ${totalLicenses}.`,
      pod: {
        _id: pod._id,
        name: pod.name,
        type: pod.type,
      },
      licenses: {
        total: totalLicenses,
        assigned,
        available,
        previousTotal,
      },
    });
  } catch (error) {
    console.error("❌ Error setting pod licenses:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Add more licenses to an existing pod (Super Admin only)
 * @route POST /api/pods/:podId/licenses/add
 * @access Super Admin only
 */
export const addLicensesToPod = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId } = req.params;
    const { amount } = req.body;
    const requester = req.account;

    // Only super admin can add pod licenses
    if (!requester.isSuperAdmin) {
      res.status(403).json({
        message: "Access denied. Only super admins can add pod licenses.",
      });
      return;
    }

    if (typeof amount !== "number" || amount <= 0) {
      res.status(400).json({
        message: "Valid amount (positive number) is required.",
      });
      return;
    }

    const pod = await Pod.findById(podId);
    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    const previousTotal = pod.totalLicenses || 0;
    const newTotal = previousTotal + amount;
    const assigned = pod.assignedLicenses || 0;

    pod.totalLicenses = newTotal;
    await pod.save();

    await logPodActivity(
      pod._id as mongoose.Types.ObjectId,
      "add-licenses",
      `Added ${amount} licenses to pod. Total: ${previousTotal} → ${newTotal}`,
      requester._id as mongoose.Types.ObjectId,
      true
    );

    const available = Math.max(0, newTotal - assigned);

    res.status(200).json({
      message: `✅ Successfully added ${amount} licenses to pod.`,
      pod: {
        _id: pod._id,
        name: pod.name,
        type: pod.type,
      },
      licenses: {
        total: newTotal,
        assigned,
        available,
        added: amount,
        previousTotal,
      },
    });
  } catch (error) {
    console.error("❌ Error adding licenses to pod:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Super Admin Mass Upload Users to Multiple Pods
 * @route POST /api/admin/mass-upload-users
 * @access Super Admin only
 */
export const superAdminMassUploadUsers = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;

    // Only super admin can use this
    if (!requester.isSuperAdmin) {
      res.status(403).json({
        message: "Access denied. Only super admins can mass upload users.",
      });
      return;
    }

    if (!req.file?.buffer) {
      res.status(400).json({ message: "Excel file is required." });
      return;
    }

    // Parse Excel file
    const ext = path.extname(req.file.originalname).toLowerCase();
    const workbook = new ExcelJS.Workbook();
    const stream = Readable.from(req.file.buffer as any);
    const worksheet =
      ext === ".csv"
        ? await workbook.csv.read(stream)
        : (await workbook.xlsx.load(req.file.buffer as any)).worksheets[0];

    const extractCellValue = (cell: any): string =>
      typeof cell?.value === "object" && cell.value?.text
        ? cell.value.text.trim()
        : cell?.value?.toString().trim() || "";

    // Parse rows: Name, UniqueId, Email, Licenses, PodName
    const rows: any[] = [];
    worksheet?.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return; // Skip header

      const name = extractCellValue(row.getCell("A"));
      const uniqueId = extractCellValue(row.getCell("B"));
      const email = extractCellValue(row.getCell("C")).toLowerCase();
      const licensesRaw = row.getCell("D").value;
      const licenses =
        typeof licensesRaw === "number"
          ? licensesRaw
          : typeof licensesRaw === "string"
          ? parseInt(licensesRaw, 10) || 0
          : 0;
      const podName = extractCellValue(row.getCell("E"));

      if (email && podName) {
        rows.push({ name, uniqueId, email, licenses, podName });
      }
    });

    if (rows.length === 0) {
      res.status(400).json({
        message: "No valid rows found in Excel file.",
      });
      return;
    }

    // Validate emails
    const invalidEmails: string[] = [];
    const validRows = rows.filter((row) => {
      if (!validator.isEmail(row.email)) {
        invalidEmails.push(row.email);
        return false;
      }
      return true;
    });

    // Get unique pod names
    const podNames = [...new Set(validRows.map((r) => r.podName))];

    // Find all pods by name
    const pods = await Pod.find({
      name: { $in: podNames },
      isDeleted: false,
    });

    const foundPodNames = new Set(pods.map((p) => p.name));
    const missingPodNames = podNames.filter((name) => !foundPodNames.has(name));

    if (missingPodNames.length > 0) {
      res.status(404).json({
        message: "Some pods not found.",
        missingPods: missingPodNames,
      });
      return;
    }

    // Group users by pod
    const usersByPod: Map<string, any[]> = new Map();
    for (const row of validRows) {
      const existing = usersByPod.get(row.podName) || [];
      existing.push(row);
      usersByPod.set(row.podName, existing);
    }

    // Process each pod
    const results: any[] = [];
    let totalUsersAdded = 0;
    let totalUsersUpdated = 0;
    let totalLicensesAssigned = 0;

    for (const pod of pods) {
      const usersForPod = usersByPod.get(pod.name) || [];
      if (usersForPod.length === 0) continue;

      const newUsersForPod: any[] = [];
      const existingUsersForPod: any[] = [];

      // Categorize as new or existing
      for (const userData of usersForPod) {
        const existingUser = await User.findOne({ email: userData.email });
        if (existingUser) {
          existingUsersForPod.push(userData);
        } else {
          newUsersForPod.push(userData);
        }
      }

      const isLocked = pod.type !== "private";
      const profession: Profession =
        pod.type === "institution" ? "Student" : "IT Profession";

      // Add new users
      const addedUsers = await Promise.all(
        newUsersForPod.map(async (userData) => {
          const token = jwt.sign(
            { email: userData.email },
            process.env.JWT_SECRET!,
            { expiresIn: "2d" }
          );

          const newUser = new User({
            email: userData.email,
            name: pod.type === "private" ? "Pending Registration" : userData.name,
            uniqueId: userData.uniqueId || null,
            licenses: userData.licenses || 0,
            profession,
            schoolOrCollege:
              pod.type === "institution" ? (pod.institutionName || undefined) : undefined,
            organization:
              pod.type === "organization" ? (pod.organizationName || undefined) : undefined,
            educationStatus: pod.educationStatus || null,
            verificationToken: token,
            verified: false,
            profileLocked: isLocked,
          });

          await newUser.save();

          // Record license assignment
          if (userData.licenses && userData.licenses > 0) {
            await recordLicenseAssignment(
              newUser._id as mongoose.Types.ObjectId,
              userData.licenses,
              pod._id as mongoose.Types.ObjectId,
              requester._id as mongoose.Types.ObjectId,
              "Bulk Assignment",
              `Mass upload by super admin to pod "${pod.name}"`
            );
            totalLicensesAssigned += userData.licenses;

            // Update pod's assigned licenses (super admin bypasses pool check)
            pod.assignedLicenses = (pod.assignedLicenses || 0) + userData.licenses;
          }

          // Add to pod
          pod.invitedUsers.push({
            email: userData.email,
            userId: newUser._id as mongoose.Types.ObjectId,
            status: "pending",
          });

          // Send email
          if (pod.type === "private") {
            await sendPrivatePodRegistrationEmail(
              userData.email,
              token,
              pod.name
            );
          } else {
            await sendPodUserInviteEmail(userData.email, token, pod.name);
          }

          return newUser;
        })
      );

      // Update existing users
      const updatedUsers = await Promise.all(
        existingUsersForPod.map(async (userData) => {
          const user = await User.findOne({ email: userData.email });
          if (!user) return null;

          const previousLicenses = user.licenses || 0;

          // Update user details if pod requires
          if (pod.type !== "private") {
            user.profession = profession;
            user.schoolOrCollege =
              pod.type === "institution"
                ? (pod.institutionName || null)
                : user.schoolOrCollege;
            user.organization =
              pod.type === "organization"
                ? (pod.organizationName || null)
                : user.organization;
            if (pod.educationStatus) {
              user.educationStatus = pod.educationStatus;
            }
            user.profileLocked = true;
          }

          if (userData.uniqueId) {
            user.uniqueId = userData.uniqueId;
          }

          if (userData.licenses) {
            user.licenses = userData.licenses;
          }

          await user.save();

          // Record license assignment if increased
          if (userData.licenses && userData.licenses > previousLicenses) {
            const licensesDifference = userData.licenses - previousLicenses;
            await recordLicenseAssignment(
              user._id as mongoose.Types.ObjectId,
              licensesDifference,
              pod._id as mongoose.Types.ObjectId,
              requester._id as mongoose.Types.ObjectId,
              "Bulk Assignment",
              `Mass upload by super admin to pod "${pod.name}"`
            );
            totalLicensesAssigned += licensesDifference;

            // Update pod's assigned licenses
            pod.assignedLicenses = (pod.assignedLicenses || 0) + licensesDifference;
          }

          // Add to pod if not already
          const alreadyInPod = pod.invitedUsers.find(
            (i) => i.email === userData.email
          );
          if (!alreadyInPod) {
            pod.invitedUsers.push({
              email: userData.email,
              userId: user._id as mongoose.Types.ObjectId,
              status: user.verified ? "joined" : "pending",
            });
          }

          // Send notification
          await sendEmail(
            userData.email,
            "You've been added to a new pod",
            `Hello,\n\nYou've been added to the pod "${pod.name}". Please log in to your account to continue.\n\nThank you.`
          );

          return user;
        })
      );

      await pod.save();

      const addedCount = addedUsers.length;
      const updatedCount = updatedUsers.filter(Boolean).length;
      totalUsersAdded += addedCount;
      totalUsersUpdated += updatedCount;

      // Log activity
      await logPodActivity(
        pod._id as mongoose.Types.ObjectId,
        "mass-upload",
        `Super admin mass uploaded ${addedCount} new and ${updatedCount} existing users.`,
        requester._id as mongoose.Types.ObjectId,
        true
      );

      results.push({
        podId: pod._id,
        podName: pod.name,
        usersAdded: addedCount,
        usersUpdated: updatedCount,
        totalUsers: addedCount + updatedCount,
      });
    }

    res.status(200).json({
      message: "✅ Mass upload completed successfully!",
      summary: {
        totalPodsAffected: pods.length,
        totalUsersAdded,
        totalUsersUpdated,
        totalLicensesAssigned,
        invalidEmails: invalidEmails.length > 0 ? invalidEmails : undefined,
      },
      podResults: results,
    });
  } catch (error) {
    console.error("❌ Error in super admin mass upload:", error);
    res.status(500).json({
      message: "Internal server error during mass upload.",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }
};

/**
 * @desc Preview Super Admin Mass Upload
 * @route POST /api/admin/mass-upload-preview
 * @access Super Admin only
 */
export const superAdminMassUploadPreview = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;

    if (!requester.isSuperAdmin) {
      res.status(403).json({
        message: "Access denied. Only super admins can access this.",
      });
      return;
    }

    if (!req.file?.buffer) {
      res.status(400).json({ message: "Excel file is required." });
      return;
    }

    // Parse Excel
    const ext = path.extname(req.file.originalname).toLowerCase();
    const workbook = new ExcelJS.Workbook();
    const stream = Readable.from(req.file.buffer as any);
    const worksheet =
      ext === ".csv"
        ? await workbook.csv.read(stream)
        : (await workbook.xlsx.load(req.file.buffer as any)).worksheets[0];

    const extractCellValue = (cell: any): string =>
      typeof cell?.value === "object" && cell.value?.text
        ? cell.value.text.trim()
        : cell?.value?.toString().trim() || "";

    const rows: any[] = [];
    worksheet?.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return;

      const name = extractCellValue(row.getCell("A"));
      const uniqueId = extractCellValue(row.getCell("B"));
      const email = extractCellValue(row.getCell("C")).toLowerCase();
      const licensesRaw = row.getCell("D").value;
      const licenses =
        typeof licensesRaw === "number"
          ? licensesRaw
          : typeof licensesRaw === "string"
          ? parseInt(licensesRaw, 10) || 0
          : 0;
      const podName = extractCellValue(row.getCell("E"));

      if (email && podName) {
        rows.push({ name, uniqueId, email, licenses, podName });
      }
    });

    // Validate and group
    const invalidEmails: string[] = [];
    const validRows = rows.filter((row) => {
      if (!validator.isEmail(row.email)) {
        invalidEmails.push(row.email);
        return false;
      }
      return true;
    });

    const podNames = [...new Set(validRows.map((r) => r.podName))];
    const pods = await Pod.find({
      name: { $in: podNames },
      isDeleted: false,
    });

    const foundPodNames = new Set(pods.map((p) => p.name));
    const missingPodNames = podNames.filter((name) => !foundPodNames.has(name));

    // Group by pod
    const usersByPod: any = {};
    for (const row of validRows) {
      if (!usersByPod[row.podName]) {
        usersByPod[row.podName] = [];
      }
      usersByPod[row.podName].push({
        name: row.name,
        email: row.email,
        uniqueId: row.uniqueId,
        licenses: row.licenses,
      });
    }

    res.status(200).json({
      message: "Preview generated successfully.",
      summary: {
        totalRows: rows.length,
        validRows: validRows.length,
        invalidEmails,
        podsFound: pods.length,
        missingPods: missingPodNames,
      },
      usersByPod,
      pods: pods.map((p) => ({
        id: p._id,
        name: p.name,
        type: p.type,
        currentLicenses: {
          total: p.totalLicenses || 0,
          assigned: p.assignedLicenses || 0,
          available: Math.max(0, (p.totalLicenses || 0) - (p.assignedLicenses || 0)),
        },
      })),
    });
  } catch (error) {
    console.error("❌ Error in mass upload preview:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};
