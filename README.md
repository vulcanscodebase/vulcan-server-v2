# ⚡ Vulcans Server v2

A modern backend for the **Vulcans Academy** platform, built with **Node.js**, **Express**, and **MongoDB**.
This backend handles authentication, role-based access control, and admin management.

---

## 🚀 Tech Stack

- **Node.js + Express.js** — Backend Framework
- **MongoDB + Mongoose** — Database
- **TypeScript** — Static Typing
- **SendGrid + Nodemailer** — Email Service
- **Passport.js + JWT** — Authentication
- **Docker** — Containerized MongoDB Setup
- **CORS**, **dotenv**, **morgan**, **cookie-parser**, etc. — Middleware Utilities

---

## 📁 Project Structure

```
vulcan-server-v2/
│
├── src/
│   ├── config/         # Database, passport, environment configs
│   ├── models/         # Mongoose schemas
│   ├── routes/         # Express routes
│   ├── middlewares/    # Authentication, validation, error handling
│   ├── utils/          # Helper utilities
│   └── server.ts       # Main entry point
│
├── .env.example        # Example environment variables
├── package.json
├── tsconfig.json
└── README.md
```

---

## ⚙️ Setup Instructions

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/vulcanscodebase/vulcan-server-v2.git
cd vulcan-server-v2
```

### 2️⃣ Install Dependencies

```bash
npm install
```

_or (if you prefer yarn):_

```bash
yarn install
```

---

## 🧩 MongoDB Setup Options

You can connect your backend to MongoDB using one of three methods:

### 🐳 Option 1: MongoDB via Docker (Recommended for Local Dev)

**Pull the MongoDB Image:**

```bash
docker pull mongo:latest
```

**Run MongoDB Container:**

```bash
docker run -d \
  --name mongodb \
  -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=secret \
  mongo:latest
```

**Verify MongoDB is Running:**

```bash
docker ps
```

✅ Expected Output:

```
CONTAINER ID   IMAGE          COMMAND                  STATUS         PORTS
abc12345       mongo:latest   "docker-entrypoint..."   Up 10 seconds  0.0.0.0:27017->27017/tcp
```

**Use this in `.env`:**

```bash
MONGO_URI=mongodb://admin:secret@localhost:27017/vulcan_db?authSource=admin
```

💡 For persistent data storage:

```bash
docker run -d \
  --name mongodb \
  -p 27017:27017 \
  -v mongodb_data:/data/db \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=secret \
  mongo:latest
```

---

### 🧭 Option 2: MongoDB Compass (Local GUI Client)

1. Open MongoDB Compass.
2. Connect using:

   ```bash
   mongodb://localhost:27017
   ```

3. Create a new database:

   - **Database name:** `vulcan_db`
   - **Collection name:** `admins`

**Use this in `.env`:**

```bash
MONGO_URI=mongodb://localhost:27017/vulcan_db
```

---

### ☁️ Option 3: MongoDB Atlas (Cloud)

1. Visit [MongoDB Atlas](https://cloud.mongodb.com)
2. Create a project and cluster.
3. Whitelist your IP (e.g. `0.0.0.0/0` for local testing).
4. Create a database user and password.

**Use this connection string in `.env`:**

```bash
MONGO_URI=mongodb+srv://<username>:<password>@cluster0.xxxxx.mongodb.net/vulcan_db?retryWrites=true&w=majority
```

---

## 🔐 Environment Variables

Create a `.env` file in the project root:

```bash
# SERVER CONFIGURATION
PORT=5000
NODE_ENV=development
FRONTEND_URL=http://localhost:5173
BACKEND_URL=http://localhost:5000

# DATABASE (MongoDB)
MONGO_URI=mongodb://localhost:27017/vulcan_db

# JWT CONFIG
JWT_SECRET=your_jwt_secret_key_here
JWT_REFRESH_SECRET=your_jwt_refresh_secret_here

# SESSION CONFIG
SESSION_SECRET=your_session_secret_here

# GOOGLE OAUTH 2.0 CREDENTIALS
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here
GOOGLE_CALLBACK_URL=http://localhost:5000/api/auth/google/callback

# SUPER ADMIN INITIALIZATION
SUPER_ADMIN_EMAIL=admin_email_here
SUPER_ADMIN_PASSWORD=strong_admin_password_here

# EMAIL SERVICE CONFIGURATION (SendGrid)
SENDGRID_API_KEY=your_sendgrid_api_key_here
FROM_EMAIL=your_verified_sendgrid_email@example.com

# SMTP CONFIGURATION
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=smtp_user_here
SMTP_PASS=smtp_password_here
```

📄 You can copy from `.env.example` and rename it to `.env`.

---

## 🧠 Database Connection

The connection logic is defined in `src/config/db.ts`:

- Retries connection with exponential backoff.
- Handles graceful shutdowns.
- Enables Mongoose debug logs based on environment.

---

## 🧰 Running the Server

### Development Mode

```bash
npm run dev
```

(Uses `ts-node-dev` or `nodemon` depending on setup)

### Production Mode

```bash
npm run build
npm start
```

✅ **Verification:**

Once running, you should see logs like:

```
✅ MongoDB Connected: localhost
✅ Super Admin initialization completed.
🚀 Server running on port 5000
```

Visit:

```bash
http://localhost:5000/
```

Response:

```
✅ API is running...
```

---

## 🩺 Health Check Route

**Endpoint:**

```bash
GET /health
```

**Response:**

```json
{
  "status": "Healthy",
  "uptime": 123.45
}
```

---

## 🧩 API Routes Overview

| Endpoint                    | Method | Description              |
| --------------------------- | ------ | ------------------------ |
| `/api/auth/signup`          | POST   | Register new user/admin  |
| `/api/auth/signin`          | POST   | Login with JWT           |
| `/api/auth/logout`          | POST   | Logout user              |
| `/api/auth/forgot-password` | POST   | Send password reset link |
| `/api/auth/reset-password`  | POST   | Reset password           |

---

## 🛠 Common Issues

❌ **ECONNREFUSED 127.0.0.1:27017**
MongoDB is not running locally.
👉 Run `docker start mongodb` or open MongoDB Compass.

❌ **PathError: Missing parameter name**
Caused by invalid CORS configuration.
👉 Ensure `FRONTEND_URL` is a plain URL (e.g. `http://localhost:3000`).

❌ **Super Admin not found**
👉 Ensure roles are seeded before running the server.

---

## 🧹 Stopping Docker Container

```bash
docker stop mongodb
```

To remove completely:

```bash
docker rm -f mongodb
```

---

## 🧱 (Optional) Docker Compose Setup

If you want to spin up **MongoDB and the backend together**, create a `docker-compose.yml` like this:

```yaml
version: "3.8"
services:
  backend:
    build: .
    container_name: vulcan-backend
    ports:
      - "5000:5000"
    env_file: .env
    depends_on:
      - mongodb

  mongodb:
    image: mongo:latest
    container_name: mongodb
    restart: always
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: secret
    volumes:
      - mongodb_data:/data/db

volumes:
  mongodb_data:
```

Then simply run:

```bash
docker-compose up --build
```

---

## 🏁 That’s It!

You now have the Vulcans Backend Server fully running with:

- MongoDB (Docker / Compass / Atlas)
- Secure `.env` configuration
- Automatic Super Admin setup

---

**Maintained by:**
👨‍💻 Tejas
