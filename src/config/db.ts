import mongoose from "mongoose";
import process from "process";

const connectDB = async () => {
  const MAX_RETRIES = 5; // Maximum number of retry attempts
  const INITIAL_RETRY_DELAY = 5000; // Initial delay in milliseconds between retries
  let retries = 0;

  // 🛠 Updated MongoDB Connection Options
  const mongoOptions = {
    connectTimeoutMS: 60000, // ⏳ Increased timeout for slow connections
    socketTimeoutMS: 60000, // ⏳ Increased socket timeout
    serverSelectionTimeoutMS: 60000, // ⏳ Increased server selection timeout
    maxPoolSize: 10, // 🛠 Manage connections efficiently
    autoIndex: true, // 🛠 Ensure indexes are built automatically
    family: 4, // 🛠 Use IPv4, prevents certain connection issues
    retryWrites: true, // 🛠 Enable retryable writes
  };

  // 🛠 Recursive function with exponential backoff
  const connect = async () => {
    try {
      // Ensure MONGO_URI is provided and typed
      const mongoUri = process.env.MONGO_URI;
      if (!mongoUri) {
        console.error("❌ MONGO_URI is not set in environment. Exiting...");
        process.exit(1);
      }

      // 🛠 Removed deprecated options
      const conn = await mongoose.connect(mongoUri, mongoOptions as any);
      console.log(`✅ MongoDB Connected: ${conn.connection.host}`);

      // 🛠 Toggle Mongoose Debug Mode based on .env setting
      if (process.env.MONGOOSE_DEBUG === "true") {
        mongoose.set("debug", true);
        console.log("🔍 Mongoose Debug Mode: ENABLED");
      } else {
        console.log("🔍 Mongoose Debug Mode: DISABLED");
      }
    } catch (error: any) {
      console.error(`❌ MongoDB Connection Error: ${error?.message || error}`);

      if (retries < MAX_RETRIES) {
        retries++;
        const retryDelay = INITIAL_RETRY_DELAY * retries; // 🛠 Exponential backoff
        console.log(
          `🔄 Retrying connection (${retries}/${MAX_RETRIES}) in ${
            retryDelay / 1000
          } seconds...`
        );
        setTimeout(connect, retryDelay);
      } else {
        console.error("❌ Max retries reached. Exiting...");
        process.exit(1);
      }
    }
  };

  await connect();

  // 🛠 Graceful Shutdown Handling
  const handleExit = async (signal: NodeJS.Signals | string) => {
    console.log(`⚠️ ${signal} received. Closing MongoDB connection...`);
    try {
      await mongoose.connection.close();
      console.log("✅ MongoDB connection closed.");
      process.exit(0);
    } catch (error) {
      const err: any = error;
      console.error(
        "❌ Error during MongoDB disconnection:",
        err?.message || err
      );
      process.exit(1);
    }
  };

  process.on("SIGINT", handleExit);
  process.on("SIGTERM", handleExit);
};

export default connectDB;
