import mongoose, { Document, Schema } from "mongoose";
import bcrypt from "bcryptjs";
import { SignJWT } from "jose";

export interface IUser extends Document {
  name: string;
  dob?: Date | null;
  email: string;
  password?: string;
  googleId?: string | null;
  profilePhoto?: string | null;
  googleRefreshToken?: string | null;
  educationStatus?:
    | "10th or below"
    | "11th-12th or diploma"
    | "Undergrad"
    | "Grad"
    | "Post Grad"
    | null;
  schoolOrCollege?: string | null;
  profession?:
    | "Student"
    | "IT Profession"
    | "Job Seeker"
    | "Aspirant Studying Abroad"
    | null;
  organization?: string | null;
  qualification?: string | null;
  purchasedTests?: mongoose.Types.ObjectId[];
  purchasedCourses?: mongoose.Types.ObjectId[];
  reportCards?: mongoose.Types.ObjectId[];
  resetPasswordToken?: string | null;
  resetPasswordExpire?: Date | null;
  verified?: boolean;
  verificationToken?: string | null;
  profileLocked?: boolean;

  // Methods
  matchPassword(enteredPassword: string): Promise<boolean>;
  getSignedJwtToken(): string;

  // Virtuals
  isBasicRegistrationComplete: boolean;
  isProfileComplete: boolean;
}

const userSchema = new Schema<IUser>(
  {
    name: {
      type: String,
      required: [true, "User name is required."],
      trim: true,
      minlength: [3, "Name must be at least 3 characters long."],
      maxlength: [50, "Name cannot exceed 50 characters."],
    },
    dob: { type: Date, default: null },
    email: {
      type: String,
      required: [true, "Email is required."],
      unique: true,
      lowercase: true,
      trim: true,
      match: [
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        "Please provide a valid email address.",
      ],
    },
    password: {
      type: String,
      required: function (this: IUser) {
        return !this.googleId && !this.verificationToken;
      },
      minlength: [8, "Password must be at least 8 characters long."],
    },
    googleId: { type: String, default: null, unique: true, sparse: true },
    profilePhoto: { type: String, default: null },
    googleRefreshToken: { type: String, default: null },
    educationStatus: {
      type: String,
      enum: [
        "10th or below",
        "11th-12th or diploma",
        "Undergrad",
        "Grad",
        "Post Grad",
      ],
      default: null,
    },
    schoolOrCollege: { type: String, trim: true, default: null },
    profession: {
      type: String,
      enum: [
        "Student",
        "IT Profession",
        "Job Seeker",
        "Aspirant Studying Abroad",
      ],
      default: null,
    },
    organization: { type: String, default: null },
    qualification: { type: String, default: null },
    purchasedTests: [{ type: mongoose.Schema.Types.ObjectId, ref: "Test" }],
    purchasedCourses: [{ type: mongoose.Schema.Types.ObjectId, ref: "Course" }],
    reportCards: [{ type: mongoose.Schema.Types.ObjectId, ref: "Report" }],
    resetPasswordToken: { type: String, default: null },
    resetPasswordExpire: { type: Date, default: null },
    verified: { type: Boolean, default: false },
    verificationToken: { type: String, default: null },
    profileLocked: { type: Boolean, default: false },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ✅ Virtuals
userSchema.virtual("isBasicRegistrationComplete").get(function (this: IUser) {
  return !!(
    this.name &&
    this.email &&
    (this.password || this.googleId) &&
    this.verified
  );
});

userSchema.virtual("isProfileComplete").get(function (this: IUser) {
  return !!(
    this.dob &&
    this.profession &&
    ((this.profession === "Student" &&
      this.educationStatus &&
      this.schoolOrCollege) ||
      (this.profession === "IT Profession" && this.organization) ||
      (this.profession === "Job Seeker" && this.qualification) ||
      (this.profession === "Aspirant Studying Abroad" && this.qualification))
  );
});

// 🔐 Password Hashing
userSchema.pre("save", async function (next) {
  const user = this as IUser;
  if (!user.isModified("password") || !user.password) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password, salt);
    next();
  } catch (err) {
    next(err as Error);
  }
});

// 🔑 Compare Password
userSchema.methods.matchPassword = async function (
  enteredPassword: string
): Promise<boolean> {
  if (!this.password) return false;
  return bcrypt.compare(enteredPassword, this.password);
};

// 🔑 Generate JWT
userSchema.methods.getSignedJwtToken = async function (): Promise<string> {
  const secret = new TextEncoder().encode(process.env.JWT_SECRET);
  const token = await new SignJWT({
    id: this._id.toString(),
    email: this.email,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime("15m")
    .sign(secret);
  return token;
};

// Indexes
userSchema.index({ verified: 1 });
userSchema.index({ profession: 1 });

export const User = mongoose.model<IUser>("User", userSchema);
