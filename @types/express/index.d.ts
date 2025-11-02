import { IUser } from "../../models/User";
import { IAdmin } from "../../models/Admin";
import { IDeveloper } from "../../models/Developer";

declare global {
  namespace Express {
    interface Request {
      account?: IUser | IAdmin | IDeveloper;
      user?: IUser;
      developer?: IDeveloper;
      role?: "admin" | "super-admin" | "user" | "developer";
      isSuperAdmin?: boolean;
    }
  }
}
