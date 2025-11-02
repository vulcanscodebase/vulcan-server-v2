import mongoose, { Document, Types, Schema, Model } from "mongoose";
import bcrypt from "bcryptjs";
import { SignJWT } from "jose";
import type { IRole, Role } from "./Role.js";

interface Permission {
  feature: string;
  actions: ("view" | "create" | "edit" | "delete" | "publish")[];
  isPermanent?: boolean;
  expiresAt?: Date | null;
}

export interface IAdmin extends Document {
  name: string;
  email: string;
  password?: string;
  googleId?: string;
  profilePhoto?: string;
  role?: Types.ObjectId | IRole;
  allowedToCreateRoles: string[];
  isSuperAdmin: boolean;
  rolePermissions?: Permission[];
  customPermissions?: Permission[];
  extraPermissions?: Permission[];
  canCreateRoles?: boolean;
  canGrantExtraPermissions?: boolean;
  canCreateUser?: boolean;
  canUpdateUser?: boolean;
  canDeleteUser?: boolean;
  passwordResetToken?: string;
  passwordResetExpires?: Date;
  verified: boolean;

  generateAccessToken(): Promise<string>;
  generatePasswordResetToken(): Promise<string>;

  matchPassword(enteredPassword: string): Promise<boolean>;
  getSignedJwtToken(): string;
  getResetPasswordToken(): string;
}

const adminSchema = new mongoose.Schema<IAdmin>(
  {
    name: {
      type: String,
      required: [true, "Admin name is required."],
      trim: true,
    },
    email: {
      type: String,
      required: [true, "Admin email is required."],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, "Please provide a valid email address."],
      index: true,
    },
    password: {
      type: String,
      minlength: [8, "Password must be at least 8 characters long."],
      required: function (this: IAdmin) {
        return !this.googleId;
      },
      select: false, // Hide password by default
    },
    googleId: { type: String, default: null },
    profilePhoto: { type: String, default: null },

    role: {
      type: Schema.Types.ObjectId,
      ref: "Role",
      required: function () {
        return !this.isSuperAdmin;
      },
    },

    isSuperAdmin: { type: Boolean, default: false },

    // Permissions
    rolePermissions: [
      {
        feature: { type: String, required: true },
        actions: [
          {
            type: String,
            enum: ["view", "create", "edit", "delete", "publish"],
          },
        ],
      },
    ],

    customPermissions: [
      {
        feature: { type: String, required: true },
        actions: [
          {
            type: String,
            enum: ["view", "create", "edit", "delete", "publish"],
          },
        ],
      },
    ],

    extraPermissions: [
      {
        feature: { type: String, required: true },
        actions: [
          {
            type: String,
            enum: ["view", "create", "edit", "delete", "publish"],
          },
        ],
        isPermanent: { type: Boolean, default: false },
        expiresAt: { type: Date, default: null },
      },
    ],

    // Role & user management flags
    canCreateRoles: { type: Boolean, default: false },
    canGrantExtraPermissions: { type: Boolean, default: false },
    canCreateUser: { type: Boolean, default: false },
    canUpdateUser: { type: Boolean, default: false },
    canDeleteUser: { type: Boolean, default: false },

    // Reset & verification
    passwordResetToken: { type: String, default: null },
    passwordResetExpires: { type: Date, default: null },

    verified: { type: Boolean, default: false },
  },
  { timestamps: true }
);

// 🔒 Hash password before saving
adminSchema.pre("save", async function (next) {
  if (!this.isModified("password") || !this.password) return next();

  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    console.error("❌ Error hashing password:", err);
    next(err as Error);
  }
});

// 🧠 Compare password method
adminSchema.methods.matchPassword = async function (enteredPassword: string) {
  return bcrypt.compare(enteredPassword, this.password);
};

// 🪙 Generate JWT access token (using JOSE)
adminSchema.methods.generateAccessToken = async function () {
  const secret = new TextEncoder().encode(process.env.JWT_SECRET);
  return await new SignJWT({
    id: this._id.toString(),
    email: this.email,
    isSuperAdmin: this.isSuperAdmin,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime(process.env.JWT_EXPIRE || "1h")
    .sign(secret);
};

// 🔑 Generate password reset token
adminSchema.methods.generatePasswordResetToken = async function () {
  const secret = new TextEncoder().encode(process.env.JWT_SECRET);
  const token = await new SignJWT({ id: this._id.toString() })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime("15m")
    .sign(secret);

  this.passwordResetToken = token;
  this.passwordResetExpires = Date.now() + 15 * 60 * 1000; // 15 mins
  return token;
};

export const Admin: Model<IAdmin> = mongoose.model<IAdmin>(
  "Admin",
  adminSchema
);
