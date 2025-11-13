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
          defaultPermissions: [{ feature: "Groups", actions: ["view"] }],
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

    const pods = await Pod.find(query)
      .populate("createdBy", "name email")
      .sort({ createdAt: -1 });

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
      const email = extractCellValue(row.getCell("B")).toLowerCase();
      const qualification = extractCellValue(row.getCell("C"));
      const dobRaw = row.getCell("D").value;
      const dob =
        typeof dobRaw === "string" ||
        typeof dobRaw === "number" ||
        dobRaw instanceof Date
          ? new Date(dobRaw)
          : null;
      if (email) rows.push({ name, email, qualification, dob });
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
        qualification: pod.type !== "private" ? row.qualification : undefined,
        dob: pod.type !== "private" ? row.dob : undefined,
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
      const email = extractCellValue(row.getCell("B")).toLowerCase();
      const qualification = extractCellValue(row.getCell("C"));
      const dobRaw = row.getCell("D").value;
      const dob =
        typeof dobRaw === "string" ||
        typeof dobRaw === "number" ||
        dobRaw instanceof Date
          ? new Date(dobRaw)
          : null;
      if (email) rows.push({ name, email, qualification, dob });
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

        await existing.save();

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
    const { name, email, qualification, dob } = req.body;
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
      if (profileLocked && user) {
        Object.assign(user, userDetails);
        await user.save();
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

    // ✅ Activity Log
    await logPodActivity(
      pod._id as mongoose.Types.ObjectId,
      "remove-user",
      `User ${user?.email || userId} removed from pod "${pod.name}"`,
      requester._id as mongoose.Types.ObjectId,
      true
    );

    console.log(`✅ User ${userId} removed from pod ${pod.name}`);
    res.status(200).json({
      message: "User removed from pod successfully.",
      podId: pod._id,
      removedUserId: userId,
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

    pod.isDeleted = true;
    pod.deletedAt = new Date();
    await pod.save();

    console.log(`✅ Pod '${pod.name}' soft deleted.`);

    await logPodActivity(
      pod._id as mongoose.Types.ObjectId,
      "soft-delete",
      `Pod was soft-deleted by ${requester.email}`,
      requester._id as mongoose.Types.ObjectId
    );

    res.status(200).json({ message: "Pod has been soft deleted." });
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

    const userIds = (pod.invitedUsers.map((invite) => invite.userId) as any[])
      .filter(Boolean);

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
