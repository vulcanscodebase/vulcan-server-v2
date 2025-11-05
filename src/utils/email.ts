import sgMail from "@sendgrid/mail";
import dotenv from "dotenv";
import nodemailer from "nodemailer";

dotenv.config();

const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY || "";
const FROM_EMAIL = process.env.FROM_EMAIL || "no-reply@vulcans.academy";
const SMTP_HOST = process.env.SMTP_HOST || "smtp.gmail.com";
const SMTP_PORT = Number(process.env.SMTP_PORT) || 587;
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";

// ✅ Initialize SendGrid
if (SENDGRID_API_KEY) {
  sgMail.setApiKey(SENDGRID_API_KEY);
} else {
  console.warn("⚠️ SENDGRID_API_KEY not found — will use Nodemailer only.");
}

// ✅ Configure Nodemailer fallback
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_PORT === 465, // true for 465, false for others
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASS,
  },
});

// ✅ Define the sendEmail function with TypeScript types
export const sendEmail = async (
  to: string,
  subject: string,
  text: string
): Promise<void> => {
  const msg = {
    to,
    from: {
      email: FROM_EMAIL,
      name: "Vulcans Academy",
    },
    subject,
    text,
  };

  // Try SendGrid first
  try {
    if (SENDGRID_API_KEY) {
      const response = await sgMail.send(msg);
      console.log("✅ Email sent via SendGrid:", response[0]?.statusCode);
      return;
    } else {
      console.warn("⚠️ SendGrid not configured — skipping to Nodemailer.");
    }
  } catch (error: any) {
    console.error("❌ SendGrid failed:", error.message);
    if (error.response?.body?.errors) {
      console.error("➡️", error.response.body.errors);
    }
  }

  // Fallback to Nodemailer
  try {
    const info = await transporter.sendMail({
      from: `"Vulcans Academy" <${FROM_EMAIL}>`,
      to,
      subject,
      text,
    });
    console.log("✅ Email sent via Nodemailer:", info.messageId);
  } catch (fallbackError: any) {
    console.error("❌ Nodemailer also failed:", fallbackError.message);
    throw new Error("Failed to send email via both SendGrid and Nodemailer");
  }
};

// ✅ Admin Password Setup
export const sendPasswordSetupEmail = async (
  name: string,
  email: string,
  setupToken: string
) => {
  const setupUrl = `${process.env.ADMIN_URL}/setup-password?token=${setupToken}`;
  const text = `Hello ${name},\n\nYou have been added as an admin. Please set up your password using the link below:\n\n${setupUrl}\n\nThis link expires in 24 hours.\n\nThank you.`;

  await sendEmail(email, "Set Up Your Admin Account", text);
};
