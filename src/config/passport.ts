import passport from "passport";
import {
  Strategy as GoogleStrategy,
  type Profile,
  type VerifyCallback,
} from "passport-google-oauth20";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { User } from "../models/User.js";

dotenv.config();

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID! as string,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET! as string,
      callbackURL:
        process.env.GOOGLE_CALLBACK_URL ||
        "http://localhost:5000/api/auth/google/callback",
      scope: ["profile", "email"],
    },
    async (
      accessToken: string,
      refreshToken: string,
      profile: Profile,
      done: VerifyCallback
    ) => {
      try {
        const { id, displayName, emails, photos } = profile;

        if (!emails || emails.length === 0) {
          throw new Error("No email found in Google profile");
        }

        let user = await User.findOne({ googleId: id });

        if (!user) {
          user = await User.findOne({ email: emails[0]?.value });

          if (user) {
            user.googleId = id;
            user.profilePhoto =
              photos?.[0]?.value ||
              user.profilePhoto ||
              "default-profile-photo-url";
            user.verified = true;
            user.googleRefreshToken = refreshToken;
            await user.save();
          } else {
            user = await User.create({
              name: displayName,
              email: emails[0]?.value,
              googleId: id,
              profilePhoto: photos?.[0]?.value || "default-profile-photo-url",
              dob: null,
              educationStatus: null,
              profession: "Student",
              schoolOrCollege: null,
              verified: true,
              googleRefreshToken: refreshToken,
              verificationToken: null,
            });
          }
        } else if (refreshToken) {
          user.googleRefreshToken = refreshToken;
          await user.save();
        }

        // ✅ Generate JWT tokens
        const accessTokenJWT = jwt.sign(
          { userId: user._id, email: user.email },
          process.env.JWT_SECRET as string,
          { expiresIn: "15m" }
        );

        const refreshTokenJWT = jwt.sign(
          { userId: user._id, email: user.email },
          process.env.JWT_REFRESH_SECRET as string,
          { expiresIn: "7d" }
        );

        // ✅ Pass both user and tokens
        done(null, user, { accessTokenJWT, refreshTokenJWT });
      } catch (error) {
        console.error("❌ Error in Google Strategy:", error);
        done(error, undefined);
      }
    }
  )
);

// ✅ Serialize and Deserialize user
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

export default passport;
