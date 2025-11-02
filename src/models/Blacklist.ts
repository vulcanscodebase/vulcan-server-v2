import mongoose, { Document, Schema } from "mongoose";

export interface IBlacklist extends Document {
  token: string;
  expiresAt: Date;
  createdAt?: Date;
  updatedAt?: Date;
}

const blacklistSchema = new Schema<IBlacklist>(
  {
    token: {
      type: String,
      required: [true, "Token is required."],
      minlength: [10, "Token must be at least 10 characters long."],
      trim: true,
    },
    expiresAt: {
      type: Date,
      required: [true, "Expiration date is required."],
    },
  },
  { timestamps: true }
);

// 🕒 Automatically delete expired tokens
blacklistSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const Blacklist = mongoose.model<IBlacklist>(
  "Blacklist",
  blacklistSchema
);
