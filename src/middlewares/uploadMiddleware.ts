import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import multer from "multer";
import dotenv from "dotenv";
import { v4 as uuidv4 } from "uuid";
import path from "path";
import type { Request, Response, NextFunction } from "express";

dotenv.config();

// // ✅ Validate S3/Spaces configuration
// if (
//   !process.env.S3_ENDPOINT ||
//   !process.env.S3_BUCKET_NAME ||
//   !process.env.AWS_ACCESS_KEY_ID ||
//   !process.env.AWS_SECRET_ACCESS_KEY
// ) {
//   throw new Error(
//     "Missing required environment variables for S3 configuration. Please set S3_ENDPOINT, S3_BUCKET_NAME, AWS_ACCESS_KEY_ID, and AWS_SECRET_ACCESS_KEY."
//   );
// }

// ✅ Initialize S3 client (works with AWS S3 and DigitalOcean Spaces)
// export const s3 = new S3Client({
//   region: "auto",
//   endpoint: `https://${process.env.S3_ENDPOINT}`,
//   credentials: {
//     accessKeyId: process.env.AWS_ACCESS_KEY_ID,
//     secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
//   },
// });

const memoryStorage = multer.memoryStorage();

// ✅ Utility to stream any file to S3/Spaces and attach `.location`
// const streamFileToS3 = async (
//   req: Request,
//   file: Express.Multer.File,
//   prefix: string = "uploads/"
// ) => {
//   const ext = path.extname(file.originalname);
//   const fileName = `${prefix}${uuidv4()}${ext}`;

//   await s3.send(
//     new PutObjectCommand({
//       Bucket: process.env.S3_BUCKET_NAME,
//       Key: fileName,
//       Body: file.buffer,
//       ContentType: file.mimetype,
//       ACL: "public-read",
//     })
//   );

//   const fileUrl = `https://${process.env.S3_BUCKET_NAME}.${process.env.S3_ENDPOINT}/${fileName}`;
//   (file as any).location = fileUrl;
// };

// ✅ Excel Upload
export const uploadExcelFile = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const upload = multer({
    storage: memoryStorage,
    fileFilter: (req, file, cb) => {
      const allowed = [
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "text/csv",
        "application/vnd.ms-excel",
      ];
      if (allowed.includes(file.mimetype)) cb(null, true);
      else cb(new Error("Only .xlsx or .csv files are allowed."));
    },
    limits: { fileSize: 5 * 1024 * 1024 },
  }).single("excel");

  upload(req, res, async (err: any) => {
    if (err instanceof multer.MulterError || err) {
      return res.status(400).json({ message: err.message });
    }

    try {
      // await streamFileToS3(req, req.file!, "pod-uploads/");
      next();
    } catch (error) {
      console.error("❌ S3 Upload Error:", error);
      return res.status(500).json({ message: "Failed to upload file to S3." });
    }
  });
};

// ✅ Audio Uploads
// export const uploadMultipleAudioFiles = (
//   req: Request,
//   res: Response,
//   next: NextFunction
// ): void => {
//   const upload = multer({
//     storage: memoryStorage,
//     limits: { fileSize: 10 * 1024 * 1024 },
//     fileFilter: (req, file, cb) => {
//       const allowed = ["audio/mpeg", "audio/wav"];
//       if (allowed.includes(file.mimetype)) cb(null, true);
//       else cb(new Error("Only MP3 and WAV files allowed."));
//     },
//   }).array("audioFiles", 3);

//   upload(req, res, async (err: any) => {
//     if (err instanceof multer.MulterError || err) {
//       return res.status(400).json({ message: err.message });
//     }

//     try {
//       for (const file of req.files as Express.Multer.File[]) {
//         await streamFileToS3(req, file, "audio-uploads/");
//       }
//       next();
//     } catch (error) {
//       console.error("❌ S3 Audio Upload Error:", error);
//       return res
//         .status(500)
//         .json({ message: "Failed to upload audio files to S3." });
//     }
//   });
// };

// // ✅ Group Image Upload
// export const uploadGroupImage = (
//   req: Request,
//   res: Response,
//   next: NextFunction
// ): void => {
//   const upload = multer({
//     storage: memoryStorage,
//     limits: { fileSize: 5 * 1024 * 1024 },
//     fileFilter: (req, file, cb) => {
//       if (file.mimetype.startsWith("image/")) cb(null, true);
//       else cb(new Error("Only image files are allowed for group images."));
//     },
//   }).single("groupImage");

//   upload(req, res, async (err: any) => {
//     if (err instanceof multer.MulterError || err) {
//       return res.status(400).json({ message: err.message });
//     }

//     try {
//       await streamFileToS3(req, req.file!, "group-images/");
//       next();
//     } catch (error) {
//       console.error("❌ Group image upload error:", error);
//       return res.status(500).json({ message: "Failed to upload image to S3." });
//     }
//   });
// };

// // ✅ PDF / Section Files
// export const uploadQuestionFileResources = (
//   req: Request,
//   res: Response,
//   next: NextFunction
// ): void => {
//   const upload = multer({
//     storage: memoryStorage,
//     fileFilter: (req, file, cb) => {
//       const allowed = [
//         "audio/mpeg",
//         "audio/wav",
//         "image/png",
//         "image/jpeg",
//         "application/pdf",
//       ];
//       if (allowed.includes(file.mimetype)) cb(null, true);
//       else
//         cb(new Error("Only MP3, WAV, PNG, JPEG, and PDF files are allowed."));
//     },
//     limits: { fileSize: 20 * 1024 * 1024 },
//   }).fields([
//     { name: "mainAudio", maxCount: 2 },
//     { name: "mainImage", maxCount: 1 },
//     { name: "passagePdf", maxCount: 1 },
//   ]);

//   upload(req, res, async (err: any) => {
//     if (err instanceof multer.MulterError || err) {
//       return res.status(400).json({ message: err.message });
//     }

//     try {
//       const allFields = ["mainAudio", "mainImage", "passagePdf"];
//       for (const field of allFields) {
//         const files = (req.files as any)?.[field] || [];
//         for (const file of files) {
//           await streamFileToS3(req, file, `question-files/${field}/`);
//         }
//       }
//       next();
//     } catch (error) {
//       console.error("❌ Question file resource upload error:", error);
//       return res
//         .status(500)
//         .json({ message: "Failed to upload resource to S3." });
//     }
//   });
// };
