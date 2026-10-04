import express from "express";
import { errorHandler } from "./middleware/error-handler.js";
import authRouter from "./routes/auth.js";
import usersRouter from "./routes/users.js";
import adminRouter from "./routes/admin.js";
import staffRouter from "./routes/staff.js";

const app = express();
const PORT = process.env.PORT || 3003;

app.use(express.json());

// Health check
app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    service: "user-service",
  });
});

// API routes
app.use("/v1/auth", authRouter);
app.use("/v1/users", usersRouter);
app.use("/v1/admin", adminRouter);
app.use("/v1", staffRouter);

// Error handler
app.use(errorHandler);

if (process.env.NODE_ENV !== "test") {
  app.listen(PORT, () => {
    console.log(`User Service running on port ${PORT}`);
  });
}

export default app;
