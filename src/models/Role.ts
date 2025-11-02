import mongoose, { Document, Schema, Types } from "mongoose";

export interface IRolePermission {
  feature: string;
  actions: ("view" | "create" | "edit" | "delete" | "publish")[];
}

export interface IRole extends Document {
  name: string;
  defaultPermissions: IRolePermission[];
  createdBy: Types.ObjectId;
  createdAt?: Date;
  updatedAt?: Date;
}

const roleSchema = new Schema<IRole>(
  {
    name: {
      type: String,
      required: [true, "Role name is required."],
      unique: true,
      trim: true,
    },

    defaultPermissions: [
      {
        feature: {
          type: String,
          required: [true, "Feature name is required."],
          trim: true,
        },
        actions: {
          type: [String],
          enum: ["view", "create", "edit", "delete", "publish"],
          validate: {
            validator: (arr: string[]) => arr.length > 0,
            message: "At least one action must be defined for each feature.",
          },
        },
      },
    ],

    createdBy: {
      type: Schema.Types.ObjectId,
      ref: "Admin",
      required: [true, "CreatedBy is required."],
    },
  },
  { timestamps: true }
);

// ✅ Ensure every role has at least one permission
roleSchema.pre("save", function (next) {
  if (!this.defaultPermissions || this.defaultPermissions.length === 0) {
    return next(new Error("A role must have at least one default permission."));
  }
  next();
});

export const Role = mongoose.model<IRole>("Role", roleSchema);
