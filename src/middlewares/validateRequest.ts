import { type Request, type Response, type NextFunction } from "express";
import { validationResult, type ValidationError } from "express-validator";

const validateRequest = (req: Request, res: Response, next: NextFunction) => {
  const result = validationResult(req);

  if (!result.isEmpty()) {
    // Optional: log detailed validation errors only in dev mode
    if (process.env.NODE_ENV === "development") {
      console.error("Validation Errors:", result.array());
    }

    return res.status(400).json({
      status: "error",
      message: "Validation failed",
      errors: result.array().map((error: ValidationError) => ({
        field: "param" in error ? error.param : "unknown",
        message: error.msg,
      })),
    });
  }

  next();
};

export default validateRequest;
