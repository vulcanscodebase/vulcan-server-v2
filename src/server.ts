import express, {
  type Application,
  type Request,
  type Response,
  type NextFunction,
} from "express";
import dotenv from "dotenv";
import cors from "cors";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import mongoose from "mongoose";
import http from "http";
import session from "express-session";
import passport from "./config/passport.js";

import authRoutes from "./routes/authRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";

import { initializeSuperAdmin } from "./utils/initializeSuperAdmin.js";
import connectDB from "./config/db.js";
import path from "path";
import podRoutes from "./routes/podRoutes.js";

dotenv.config();

// ✅ Environment variable validation
const requiredEnvVars = [
  "MONGO_URI",
  "JWT_SECRET",
  "PORT",
  "FRONTEND_URL",
  "SESSION_SECRET",
];
for (const key of requiredEnvVars) {
  if (!process.env[key]) {
    console.error(`❌ Missing environment variable: ${key}`);
    process.exit(1);
  }
}

const app: Application = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 5000;

// ✅ CORS Configuration
const FRONTEND_URL: string = process.env.FRONTEND_URL!; // Assumes it MUST be set

const allowedOrigins: string[] = [FRONTEND_URL, "http://localhost:3000", "http://localhost:3001"];

app.use(
  cors({
    // Dynamically check if the origin is in the allowed list
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or same-origin requests)
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        // Origin is allowed
        callback(null, true);
      } else {
        // Origin is not allowed
        callback(new Error(`CORS policy violation. Origin: ${origin}`), false);
      }
    },

    // Configuration for preflight requests and cookies
    credentials: true, // Allow cookies to be sent
    methods: ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE"], // OPTIONS is handled implicitly
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    optionsSuccessStatus: 204, // Standard for successful OPTIONS/preflight requests
  })
);

// ✅ Middleware
app.use(morgan("dev"));
app.use(cookieParser());
app.use(express.json({ limit: "50mb" })); // 50 MB payload size; increase if needed
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// ✅ Session Configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET as string,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      domain: process.env.NODE_ENV === "production" ? ".vulcans.in" : undefined,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);

// ✅ Passport Initialization
app.use(passport.initialize());
app.use(passport.session());

// ✅ Serve uploaded files statically
app.use("/uploads", express.static(path.join(process.cwd(), "uploads")));

// ✅ Routes
app.use("/api/auth", authRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/pods", podRoutes);

// ✅ Health and Root routes
app.get("/", (_req: Request, res: Response) => {
  res.send("✅ API is running...");
});

app.get("/health", (_req: Request, res: Response) => {
  res.status(200).json({ status: "Healthy", uptime: process.uptime() });
});

// ✅ Handle Undefined Routes
app.use((req: Request, res: Response) => {
  res.status(404).json({ error: "❌ Route not found" });
});

// ✅ Centralized Error Handling
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error("❌ Error:", err.message);
  res.status(err.status || 500).json({
    error: err.message || "Internal Server Error",
  });
});

// ✅ Start Server
const startServer = async () => {
  try {
    await connectDB();
    await initializeSuperAdmin();
    console.log("✅ Super Admin initialization completed.");

    // Request timeout (10 minutes)
    server.timeout = 10 * 60 * 1000;

    server.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
    });

    const gracefulShutdown = (signal: string) => {
      console.log(`⚠️ ${signal} received. Closing server...`);
      server.close(() => {
        console.log("📉 Database connection closed.");
        process.exit(0);
      });
    };

    process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
    process.on("SIGINT", () => gracefulShutdown("SIGINT"));
  } catch (error) {
    console.error("❌ Error during server startup:", error);
    process.exit(1);
  }
};

startServer();
