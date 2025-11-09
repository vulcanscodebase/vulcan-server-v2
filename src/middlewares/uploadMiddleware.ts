import multer, { MulterError } from "multer";
import path from "path";
import fs from "fs";
import type { Request, Response, NextFunction } from "express";

// ✅ Ensure upload directory exists
const ensureDir = (dir: string) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
};

// ✅ Base upload directory
const UPLOAD_BASE = path.join(process.cwd(), "uploads");

// ✅ Create multer storage config for local uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const folder = "pod-uploads";
    const dir = path.join(UPLOAD_BASE, folder);
    ensureDir(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  },
});

// ✅ Helper: get file URL/path
const getFileUrl = (filePath: string) => {
  // For dev: serve via /uploads/ route
  return `/uploads/${path.basename(filePath)}`;
};

// ✅ Excel upload middleware
export const uploadExcelFile = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
      const allowed = [
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "text/csv",
        "application/vnd.ms-excel",
      ];
      if (allowed.includes(file.mimetype)) cb(null, true);
      else cb(new Error("Only .xlsx or .csv files are allowed."));
    },
  }).single("excel");

  upload(req, res, (err: any) => {
    if (err instanceof MulterError || err) {
      res.status(400).json({ message: err.message });
      return;
    }

    if (req.file) {
      (req.file as any).location = getFileUrl(req.file.path);
    }
    next();
  });
};

// ✅ Image upload (for group/profile images)
export const uploadGroupImage = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
      if (file.mimetype.startsWith("image/")) cb(null, true);
      else cb(new Error("Only image files are allowed."));
    },
  }).single("groupImage");

  upload(req, res, (err: any) => {
    if (err instanceof MulterError || err) {
      res.status(400).json({ message: err.message });
      return;
    }

    if (req.file) {
      (req.file as any).location = getFileUrl(req.file.path);
    }
    next();
  });
};
