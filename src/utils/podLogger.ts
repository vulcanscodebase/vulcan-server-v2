import { Types } from "mongoose";
import { Pod } from "../models/Pod.js";
import { Admin } from "../models/Admin.js";
import { sendEmail } from "./email.js";

/**
 * Logs a pod-related activity and optionally notifies the pod's creator/admin.
 *
 * @param podId - ID of the pod
 * @param action - Action performed (e.g. "create", "delete", "add-user")
 * @param message - Description of what happened
 * @param performedBy - ID of the admin who performed the action
 * @param notify - Whether to email the pod's creator/admin
 */
export const logPodActivity = async (
  podId: Types.ObjectId | string,
  action: string,
  message: string,
  performedBy: Types.ObjectId | string,
  notify = false
): Promise<void> => {
  try {
    // ✅ Log activity in the pod document
    const pod = await Pod.findByIdAndUpdate(
      podId,
      {
        $push: {
          activityLogs: {
            action,
            message,
            performedBy,
            timestamp: new Date(),
          },
        },
      },
      { new: true }
    );

    // ✅ Optionally notify pod creator/admin
    if (
      notify &&
      pod &&
      pod.createdBy &&
      pod.createdBy.toString() !== performedBy?.toString()
    ) {
      const admin = await Admin.findById(pod.createdBy).select("email name");
      if (admin && admin.email) {
        await sendEmail(
          admin.email,
          `Activity Alert: ${action} on Pod "${pod.name}"`,
          `Hello ${admin.name || "Admin"},\n\n${message}\n\n— Vulcans Team`
        );
      }
    }
  } catch (err: any) {
    console.error("❌ Failed to log pod activity:", err.message);
  }
};
