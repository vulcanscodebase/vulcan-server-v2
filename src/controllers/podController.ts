import { type Request, type Response } from "express";
import fs from "fs/promises";
import path from "path";
import jwt from "jsonwebtoken";
import ExcelJS from "exceljs";
import validator from "validator";
import { Readable } from "stream";
import mongoose from "mongoose";

import { Pod } from "../models/Pod.js";
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
    } = req.body;

    if (!name || !type) {
      res.status(400).json({ message: "Pod name and type are required." });
      return;
    }

    if (!["institution", "organization", "private"].includes(type)) {
      res.status(400).json({ message: "Invalid pod type." });
      return;
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
    });

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
      `Pod "${pod.name}" created.`,
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
 * @desc Upload Excel of Pod Users (Local)
 */
export const uploadPodUsersExcel = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId } = req.params;
    const requester = req.account;

    if (!req.file?.path) {
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

    const buffer = Buffer.from(await fs.readFile(req.file.path)) as any;
    const ext = path.extname(req.file.originalname).toLowerCase();
    const workbook = new ExcelJS.Workbook();
    const worksheet =
      ext === ".csv"
        ? await workbook.csv.read(Readable.from(buffer))
        : (await workbook.xlsx.load(buffer)).worksheets[0];

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

    res.status(200).json({
      message: "Excel processed successfully.",
      newUsers,
      existingUsers,
      invalidEmails,
      filePath: req.file.path,
    });
  } catch (error) {
    console.error("❌ Error processing Excel:", error);
    res.status(500).json({ message: "Internal server error." });
  }
};

/**
 * @desc Preview Excel Data Before Adding Users
 */
export const processPodExcelPreview = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { podId } = req.params;
    const requester = req.account;

    if (!req.file?.path) {
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

    const buffer = Buffer.from(await fs.readFile(req.file.path)) as any;
    const ext = path.extname(req.file.originalname).toLowerCase();
    const workbook = new ExcelJS.Workbook();
    const worksheet =
      ext === ".csv"
        ? await workbook.csv.read(Readable.from(buffer))
        : (await workbook.xlsx.load(buffer)).worksheets[0];

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
