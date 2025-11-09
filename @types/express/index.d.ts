import { IUser } from "../../models/User";
import { IAdmin } from "../../models/Admin";
import { ICollegeMaintainer } from "../../models/CollegeMaintainer";

declare global {
  namespace Express {
    interface Request {
      account?: IUser | IAdmin | IDeveloper;
      user?: IUser;
      collegeMaintainer?: ICollegeMaintainer;
      role?: "admin" | "super-admin" | "user" | "developer";
      isSuperAdmin?: boolean;
    }
  }
}
