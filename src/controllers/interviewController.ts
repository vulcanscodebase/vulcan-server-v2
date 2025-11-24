import { type Request, type Response } from "express";
import mongoose from "mongoose";
import { Interview, type IInterview } from "../models/Interview.js";
import { User, type IUser } from "../models/User.js";
import { Transaction, type ITransaction } from "../models/Transaction.js";
import { Pod, type IPod } from "../models/Pod.js";

interface StartInterviewBody {
  jobRole?: string;
  resumeText?: string;
  resumeFileName?: string;
  resumeEvaluation?: Record<string, unknown>;
}

interface CompleteInterviewBody {
  interviewId: string;
  report?: {
    strengths?: string[];
    improvements?: string[];
    tips?: string[];
    overallFeedback?: string;
    metrics?: Record<string, unknown>;
  };
  questionsData?: Array<{
    question: string;
    questionNumber: number;
    transcript: string;
    metrics?: Record<string, unknown>;
    audioURL?: string;
  }>;
  metadata?: Record<string, unknown>;
}

interface UpdateInterviewFeedbackBody {
  report?: {
    strengths?: string[];
    improvements?: string[];
    tips?: string[];
    overallFeedback?: string;
    metrics?: Record<string, unknown>;
  };
}

/**
 * @desc Start a new interview session
 * @route POST /api/interviews/start
 * @access Private (Authenticated Users)
 */
export const startInterview = async (
  req: Request<{}, {}, StartInterviewBody>,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const userId = requester._id || requester.id;
    const { jobRole, resumeText, resumeFileName, resumeEvaluation } = req.body;

    // Validate user exists
    const user = await User.findById(userId);
    if (!user) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    // Check if user has sufficient licenses
    const currentBalance = user.licenses || 0;
    if (currentBalance < 1) {
      res.status(400).json({
        message: "Insufficient licenses to start an interview.",
        currentBalance,
        requiredLicenses: 1,
      });
      return;
    }

    // Create new interview session
    const interview = new Interview({
      userId: new mongoose.Types.ObjectId(userId),
      jobRole: jobRole || null,
      startedAt: new Date(),
      status: "started",
      resume: resumeText
        ? {
            text: resumeText,
            fileName: resumeFileName || "resume.pdf",
            evaluation: resumeEvaluation || {},
          }
        : null,
      metadata: {
        userAgent: req.get("user-agent"),
        ipAddress: req.ip,
      },
    });

    await interview.save();

    // ✅ Deduct license immediately when interview starts (after resume upload)
    const balanceBefore = currentBalance;
    const balanceAfter = balanceBefore - 1;

    // Create license deduction transaction
    const transaction = new Transaction({
      type: "deducted",
      userId: new mongoose.Types.ObjectId(userId),
      amount: 1,
      reason: "Interview Attendance",
      interviewId: new mongoose.Types.ObjectId(interview._id as mongoose.Types.ObjectId),
      description: `Interview started for ${jobRole || "general"} position`,
      performedBy: null, // User initiated, not admin
      balanceBefore,
      balanceAfter,
      status: "completed",
      metadata: {
        jobRole: jobRole || "general",
        interviewStartTime: interview.startedAt,
      },
    });

    // Update user's license balance
    user.licenses = balanceAfter;

    // Save all changes (interview, transaction, user)
    await Promise.all([transaction.save(), user.save()]);

    res.status(201).json({
      message: "Interview session started successfully and license deducted.",
      interview: {
        _id: interview._id,
        userId: interview.userId,
        jobRole: interview.jobRole,
        startedAt: interview.startedAt,
        status: interview.status,
      },
      transaction: {
        _id: transaction._id,
        type: transaction.type,
        amount: transaction.amount,
        reason: transaction.reason,
        balanceBefore,
        balanceAfter,
      },
      userBalance: {
        before: balanceBefore,
        after: balanceAfter,
        deducted: 1,
      },
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error starting interview session.",
      error: errorMessage,
    });
  }
};

/**
 * @desc Complete an interview session (license already deducted at start)
 * @route POST /api/interviews/complete
 * @access Private (Authenticated Users)
 */
export const completeInterview = async (
  req: Request<{}, {}, CompleteInterviewBody>,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const userId = requester._id || requester.id;
    const {
      interviewId,
      report,
      questionsData,
      metadata: customMetadata,
    } = req.body;

    // Validate interviewId
    if (!interviewId || !mongoose.Types.ObjectId.isValid(interviewId)) {
      res.status(400).json({ message: "Valid interviewId is required." });
      return;
    }

    // Fetch interview
    const interview = await Interview.findById(interviewId);
    if (!interview) {
      res.status(404).json({ message: "Interview session not found." });
      return;
    }

    // Verify interview belongs to the user
    if (interview.userId.toString() !== userId.toString()) {
      res.status(403).json({
        message: "You do not have permission to complete this interview.",
      });
      return;
    }

    // Verify interview status is still started or in_progress
    if (interview.status !== "started" && interview.status !== "in_progress") {
      res.status(400).json({
        message: `Cannot complete interview with status: ${interview.status}`,
      });
      return;
    }

    // ✅ License was already deducted when interview started (after resume upload)
    // No need to deduct again here

    // Update interview with completion data
    interview.status = "completed";
    interview.completedAt = new Date();
    interview.report = report || null;
    interview.questionsData = questionsData || null;
    interview.metadata = {
      ...interview.metadata,
      ...customMetadata,
      completedAt: new Date(),
    };

    // Save interview
    await interview.save();

    res.status(200).json({
      message: "Interview completed successfully.",
      interview: {
        _id: interview._id,
        status: interview.status,
        completedAt: interview.completedAt,
      },
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error completing interview session.",
      error: errorMessage,
    });
  }
};

/**
 * @desc Get interview details
 * @route GET /api/interviews/:interviewId
 * @access Private (User or Admin)
 */
export const getInterviewDetails = async (
  req: Request<{ interviewId: string }>,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const { interviewId } = req.params;

    // Validate interviewId format
    if (!mongoose.Types.ObjectId.isValid(interviewId)) {
      res.status(400).json({ message: "Invalid interviewId format." });
      return;
    }

    const interview = await Interview.findById(interviewId);
    if (!interview) {
      res.status(404).json({ message: "Interview not found." });
      return;
    }

    // Access control: User can only view their own interviews
    if (
      interview.userId.toString() !==
        (requester._id || requester.id).toString() &&
      requester.role !== "admin" &&
      !requester.isSuperAdmin
    ) {
      res.status(403).json({
        message: "You do not have permission to view this interview.",
      });
      return;
    }

    res.status(200).json({
      message: "Interview details retrieved successfully.",
      interview,
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error retrieving interview details.",
      error: errorMessage,
    });
  }
};

/**
 * @desc Get all interviews for a user
 * @route GET /api/interviews/user/:userId
 * @access Private (User or Admin)
 */
export const getUserInterviews = async (
  req: Request<{ userId: string }>,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const { userId } = req.params;
    const page = parseInt(req.query.page as string) || 1;
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
    const skip = (page - 1) * limit;

    // Validate userId format
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      res.status(400).json({ message: "Invalid userId format." });
      return;
    }

    // Access control: Users can only see their own, admins can see any
    if (
      userId !== (requester._id || requester.id).toString() &&
      requester.role !== "admin" &&
      !requester.isSuperAdmin
    ) {
      res.status(403).json({
        message: "You do not have permission to view these interviews.",
      });
      return;
    }

    const interviews = await Interview.find({
      userId: new mongoose.Types.ObjectId(userId),
    })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Interview.countDocuments({
      userId: new mongoose.Types.ObjectId(userId),
    });

    res.status(200).json({
      message: "Interviews retrieved successfully.",
      interviews,
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error retrieving user interviews.",
      error: errorMessage,
    });
  }
};

/**
 * @desc Abandon an interview session (without deducting license)
 * @route POST /api/interviews/:interviewId/abandon
 * @access Private (User)
 */
export const abandonInterview = async (
  req: Request<{ interviewId: string }>,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const { interviewId } = req.params;
    const { reason } = req.body as { reason?: string };

    // Validate interviewId format
    if (!mongoose.Types.ObjectId.isValid(interviewId)) {
      res.status(400).json({ message: "Invalid interviewId format." });
      return;
    }

    const interview = await Interview.findById(interviewId);
    if (!interview) {
      res.status(404).json({ message: "Interview not found." });
      return;
    }

    // Verify interview belongs to the user
    if (
      interview.userId.toString() !== (requester._id || requester.id).toString()
    ) {
      res.status(403).json({
        message: "You do not have permission to abandon this interview.",
      });
      return;
    }

    // Only allow abandoning if not already completed
    if (interview.status === "completed") {
      res.status(400).json({
        message: "Cannot abandon a completed interview.",
      });
      return;
    }

    interview.status = "abandoned";
    interview.metadata = {
      ...interview.metadata,
      abandonedAt: new Date(),
      abandonReason: reason || "User initiated abandonment",
    };

    await interview.save();

    res.status(200).json({
      message: "Interview abandoned successfully. No license was deducted.",
      interview: {
        _id: interview._id,
        status: interview.status,
      },
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error abandoning interview session.",
      error: errorMessage,
    });
  }
};

/**
 * @desc Update interview with feedback/report
 * @route PUT /api/interviews/:interviewId/feedback
 * @access Private (Authenticated Users)
 */
export const updateInterviewFeedback = async (
  req: Request<{ interviewId: string }, {}, UpdateInterviewFeedbackBody>,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const userId = requester._id || requester.id;
    const { interviewId } = req.params;
    const { report } = req.body;

    // Validate interviewId
    if (!interviewId || !mongoose.Types.ObjectId.isValid(interviewId)) {
      res.status(400).json({ message: "Valid interviewId is required." });
      return;
    }

    // Fetch interview
    const interview = await Interview.findById(interviewId);
    if (!interview) {
      res.status(404).json({ message: "Interview session not found." });
      return;
    }

    // Verify interview belongs to the user
    if (interview.userId.toString() !== userId.toString()) {
      res.status(403).json({
        message: "You do not have permission to update this interview.",
      });
      return;
    }

    // Update only the report field
    interview.report = report || null;
    await interview.save();

    res.status(200).json({
      message: "Interview feedback updated successfully.",
      interview: {
        _id: interview._id,
        status: interview.status,
        report: interview.report,
      },
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error updating interview feedback.",
      error: errorMessage,
    });
  }
};

/**
 * @desc Get all interview reports by pod (Admin only)
 * @route GET /api/interviews/pod/:podId/reports
 * @access Private (Admin/SuperAdmin only)
 */
export const getPodInterviewReports = async (
  req: Request<{ podId: string }>,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const { podId } = req.params;
    const page = parseInt(req.query.page as string) || 1;
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
    const skip = (page - 1) * limit;
    const status = req.query.status as string | undefined;

    // Authorization: Only admin or super admin
    if (requester.role !== "admin" && !requester.isSuperAdmin) {
      res.status(403).json({
        message: "Access denied. Admin or Super Admin privileges required.",
      });
      return;
    }

    // Validate podId
    if (!mongoose.Types.ObjectId.isValid(podId)) {
      res.status(400).json({ message: "Invalid podId format." });
      return;
    }

    // Fetch pod
    const pod = await Pod.findById(podId);
    if (!pod) {
      res.status(404).json({ message: "Pod not found." });
      return;
    }

    // Get all user IDs from the pod's invitedUsers who have joined
    const userIds = pod.invitedUsers
      .filter((invitedUser) => invitedUser.userId && invitedUser.status === "joined")
      .map((invitedUser) => invitedUser.userId);

    if (userIds.length === 0) {
      res.status(200).json({
        message: "No users found in this pod.",
        pod: {
          _id: pod._id,
          name: pod.name,
          type: pod.type,
        },
        interviews: [],
        pagination: {
          total: 0,
          page,
          limit,
          pages: 0,
        },
      });
      return;
    }

    // Build query
    const query: any = {
      userId: { $in: userIds },
    };

    if (status) {
      query.status = status;
    }

    // Fetch interviews with user details
    const interviews = await Interview.find(query)
      .populate("userId", "name email profilePhoto educationStatus profession")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Interview.countDocuments(query);

    res.status(200).json({
      message: "Pod interview reports retrieved successfully.",
      pod: {
        _id: pod._id,
        name: pod.name,
        type: pod.type,
        institutionName: pod.institutionName,
        organizationName: pod.organizationName,
      },
      interviews,
      statistics: {
        totalInterviews: total,
        totalUsers: userIds.length,
      },
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error retrieving pod interview reports.",
      error: errorMessage,
    });
  }
};

/**
 * @desc Get all interview reports across all pods (Admin only)
 * @route GET /api/interviews/admin/all-reports
 * @access Private (Admin/SuperAdmin only)
 */
export const getAllInterviewReports = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const page = parseInt(req.query.page as string) || 1;
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
    const skip = (page - 1) * limit;
    const status = req.query.status as string | undefined;
    const podId = req.query.podId as string | undefined;

    // Authorization: Only admin or super admin
    if (requester.role !== "admin" && !requester.isSuperAdmin) {
      res.status(403).json({
        message: "Access denied. Admin or Super Admin privileges required.",
      });
      return;
    }

    // Build query
    const query: any = {};

    if (status) {
      query.status = status;
    }

    // ✅ For regular admins (not super admin), filter by their managed pods
    let userIds: mongoose.Types.ObjectId[] | undefined;
    if (!requester.isSuperAdmin) {
      // Get all pods managed or created by this admin
      const managedPods = await Pod.find({
        $or: [
          { managedBy: requester._id },
          { createdBy: requester._id },
        ],
        isDeleted: false,
      });

      // Get all user IDs from managed pods
      const allUserIds: mongoose.Types.ObjectId[] = [];
      for (const pod of managedPods) {
        const podUserIds = pod.invitedUsers
          .filter((invitedUser) => invitedUser.userId && invitedUser.status === "joined")
          .map((invitedUser) => invitedUser.userId) as mongoose.Types.ObjectId[];
        allUserIds.push(...podUserIds);
      }

      if (allUserIds.length === 0) {
        // Admin has no users in their pods
        res.status(200).json({
          message: "No interview reports found for your managed pods.",
          interviews: [],
          pagination: {
            total: 0,
            page,
            limit,
            pages: 0,
          },
          statistics: {
            totalInterviews: 0,
            completedInterviews: 0,
            inProgressInterviews: 0,
            abandonedInterviews: 0,
          },
        });
        return;
      }

      userIds = allUserIds;
    }

    // If podId is provided, filter by pod users (overrides admin's managed pods filter)
    if (podId) {
      if (!mongoose.Types.ObjectId.isValid(podId)) {
        res.status(400).json({ message: "Invalid podId format." });
        return;
      }
      const pod = await Pod.findById(podId);
      if (pod) {
        userIds = pod.invitedUsers
          .filter((invitedUser) => invitedUser.userId && invitedUser.status === "joined")
          .map((invitedUser) => invitedUser.userId) as mongoose.Types.ObjectId[];
      }
    }

    // Apply user filter if we have userIds
    if (userIds && userIds.length > 0) {
      query.userId = { $in: userIds };
    } else if (userIds && userIds.length === 0) {
      // No users found, return empty result
      res.status(200).json({
        message: "No interview reports found.",
        interviews: [],
        pagination: {
          total: 0,
          page,
          limit,
          pages: 0,
        },
        statistics: {
          totalInterviews: 0,
          completedInterviews: 0,
          inProgressInterviews: 0,
          abandonedInterviews: 0,
        },
      });
      return;
    }

    // Fetch interviews with user details
    const interviews = await Interview.find(query)
      .populate("userId", "name email profilePhoto educationStatus profession")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Interview.countDocuments(query);

    // Get statistics
    const completedCount = await Interview.countDocuments({
      ...query,
      status: "completed",
    });
    const inProgressCount = await Interview.countDocuments({
      ...query,
      status: { $in: ["started", "in_progress"] },
    });
    const abandonedCount = await Interview.countDocuments({
      ...query,
      status: "abandoned",
    });

    res.status(200).json({
      message: "All interview reports retrieved successfully.",
      interviews,
      statistics: {
        total,
        completed: completedCount,
        inProgress: inProgressCount,
        abandoned: abandonedCount,
      },
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error retrieving all interview reports.",
      error: errorMessage,
    });
  }
};

/**
 * @desc Delete an interview (Admin/SuperAdmin only)
 * @route DELETE /api/interviews/:interviewId
 * @access Private (Admin/SuperAdmin only)
 */
export const deleteInterview = async (
  req: Request<{ interviewId: string }>,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;
    const { interviewId } = req.params;

    // Authorization: Only admin or super admin
    if (requester.role !== "admin" && !requester.isSuperAdmin) {
      res.status(403).json({
        message: "Access denied. Admin or Super Admin privileges required.",
      });
      return;
    }

    // Validate interviewId
    if (!mongoose.Types.ObjectId.isValid(interviewId)) {
      res.status(400).json({ message: "Invalid interviewId format." });
      return;
    }

    // Fetch interview
    const interview = await Interview.findById(interviewId);
    if (!interview) {
      res.status(404).json({ message: "Interview not found." });
      return;
    }

    // For regular admins, verify they have access to the user's pod
    if (!requester.isSuperAdmin) {
      const user = await User.findById(interview.userId);
      if (!user) {
        res.status(404).json({ message: "User not found for this interview." });
        return;
      }

      // Check if admin manages any pod that contains this user
      const managedPods = await Pod.find({
        $or: [
          { managedBy: requester._id },
          { createdBy: requester._id },
        ],
        isDeleted: false,
      });

      const userInManagedPod = managedPods.some((pod) =>
        pod.invitedUsers.some(
          (invitedUser) =>
            invitedUser.userId?.toString() === interview.userId.toString() &&
            invitedUser.status === "joined"
        )
      );

      if (!userInManagedPod) {
        res.status(403).json({
          message: "You do not have permission to delete this interview.",
        });
        return;
      }
    }

    // Delete the interview
    await interview.deleteOne();

    res.status(200).json({
      message: "Interview deleted successfully.",
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error deleting interview.",
      error: errorMessage,
    });
  }
};

/**
 * @desc Get pod-wise interview statistics (Admin only)
 * @route GET /api/interviews/admin/pod-statistics
 * @access Private (Admin/SuperAdmin only)
 */
export const getPodInterviewStatistics = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const requester = req.account;

    // Authorization: Only admin or super admin
    if (requester.role !== "admin" && !requester.isSuperAdmin) {
      res.status(403).json({
        message: "Access denied. Admin or Super Admin privileges required.",
      });
      return;
    }

    // Fetch all pods
    const pods = await Pod.find({ isDeleted: false }).lean();

    // Build statistics for each pod
    const podStatistics = await Promise.all(
      pods.map(async (pod) => {
        const userIds = pod.invitedUsers
          .filter((invitedUser) => invitedUser.userId && invitedUser.status === "joined")
          .map((invitedUser) => invitedUser.userId);

        if (userIds.length === 0) {
          return {
            pod: {
              _id: pod._id,
              name: pod.name,
              type: pod.type,
              institutionName: pod.institutionName,
              organizationName: pod.organizationName,
            },
            statistics: {
              totalUsers: 0,
              totalInterviews: 0,
              completed: 0,
              inProgress: 0,
              abandoned: 0,
            },
          };
        }

        const totalInterviews = await Interview.countDocuments({
          userId: { $in: userIds },
        });
        const completed = await Interview.countDocuments({
          userId: { $in: userIds },
          status: "completed",
        });
        const inProgress = await Interview.countDocuments({
          userId: { $in: userIds },
          status: { $in: ["started", "in_progress"] },
        });
        const abandoned = await Interview.countDocuments({
          userId: { $in: userIds },
          status: "abandoned",
        });

        return {
          pod: {
            _id: pod._id,
            name: pod.name,
            type: pod.type,
            institutionName: pod.institutionName,
            organizationName: pod.organizationName,
          },
          statistics: {
            totalUsers: userIds.length,
            totalInterviews,
            completed,
            inProgress,
            abandoned,
          },
        };
      })
    );

    // Sort by total interviews descending
    podStatistics.sort((a, b) => b.statistics.totalInterviews - a.statistics.totalInterviews);

    res.status(200).json({
      message: "Pod-wise interview statistics retrieved successfully.",
      podStatistics,
      totalPods: pods.length,
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Internal server error";
    res.status(500).json({
      message: "Error retrieving pod interview statistics.",
      error: errorMessage,
    });
  }
};
