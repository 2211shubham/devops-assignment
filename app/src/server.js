const express = require("express");
const { Pool } = require("pg");
const fs = require("fs");
const crypto = require("crypto");

const app = express();

/**
 * Basic Express hardening
 */
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "10kb" }));

/**
 * Load secret from file first, env fallback second.
 *
 * Preferred:
 * DB_PASSWORD_FILE=/run/secrets/db_password
 *
 * Fallback:
 * DB_PASSWORD=...
 */
function loadDbPassword() {
  if (process.env.DB_PASSWORD_FILE) {
    try {
      return fs.readFileSync(process.env.DB_PASSWORD_FILE, "utf8").trim();
    } catch (err) {
      console.error("Failed to read DB_PASSWORD_FILE:", err.message);
      process.exit(1);
    }
  }

  if (process.env.DB_PASSWORD) {
    return process.env.DB_PASSWORD;
  }

  console.error("Database password is not configured");
  process.exit(1);
}

const dbPassword = loadDbPassword();

const pool = new Pool({
  host: process.env.DB_HOST || "db",
  port: Number(process.env.DB_PORT || 5432),
  database: process.env.DB_NAME || "appdb",
  user: process.env.DB_USER || "appuser",
  password: dbPassword,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});

/**
 * Optional API key middleware.
 *
 * If API_KEY is configured, POST /messages requires:
 * x-api-key: your-key
 *
 * If API_KEY is not configured, POST /messages still works.
 * This keeps the assessment easy to test, but allows stronger security when API_KEY is set.
 */
function requireApiKeyIfConfigured(req, res, next) {
  const configuredKey = process.env.API_KEY;

  if (!configuredKey) {
    return next();
  }

  const providedKey = req.header("x-api-key");

  if (!providedKey) {
    return res.status(401).json({
      error: "missing api key"
    });
  }

  const configuredBuffer = Buffer.from(configuredKey);
  const providedBuffer = Buffer.from(providedKey);

  if (
    configuredBuffer.length !== providedBuffer.length ||
    !crypto.timingSafeEqual(configuredBuffer, providedBuffer)
  ) {
    return res.status(401).json({
      error: "unauthorized"
    });
  }

  next();
}

/**
 * Routes
 */
app.get("/", (req, res) => {
  res.json({
    message: "DevOps assessment API is running"
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.status(200).json({
      status: "ok",
      db: "connected"
    });
  } catch (err) {
    console.error("Health check DB failure:", err.message);

    res.status(503).json({
      status: "degraded",
      db: "unavailable"
    });
  }
});

app.post("/messages", requireApiKeyIfConfigured, async (req, res) => {
  const text = req.body.text;

  if (!text || typeof text !== "string") {
    return res.status(400).json({
      error: "text is required"
    });
  }

  const trimmedText = text.trim();

  if (trimmedText.length === 0) {
    return res.status(400).json({
      error: "text cannot be empty"
    });
  }

  if (trimmedText.length > 500) {
    return res.status(400).json({
      error: "text must be 500 characters or less"
    });
  }

  try {
    const result = await pool.query(
      "INSERT INTO messages(text) VALUES($1) RETURNING id, text, created_at",
      [trimmedText]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("DB write failed:", err.message);

    res.status(503).json({
      error: "database unavailable"
    });
  }
});

app.get("/messages", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, text, created_at FROM messages ORDER BY id DESC LIMIT 20"
    );

    res.json(result.rows);
  } catch (err) {
    console.error("DB read failed:", err.message);

    res.status(503).json({
      error: "database unavailable"
    });
  }
});

/**
 * 404 handler
 */
app.use((req, res) => {
  res.status(404).json({
    error: "not found"
  });
});

/**
 * Generic error handler
 */
app.use((err, req, res, next) => {
  console.error("Unhandled app error:", err.message);

  res.status(500).json({
    error: "internal server error"
  });
});

/**
 * Start server.
 *
 * We do not block startup on DB connectivity.
 * Reason: if DB temporarily fails, the app should still start and expose /health as degraded.
 */
const port = process.env.PORT || 3000;

const server = app.listen(port, () => {
  console.log(`API listening on port ${port}`);
});

/**
 * Graceful shutdown
 */
async function shutdown(signal) {
  console.log(`${signal} received, shutting down gracefully`);

  try {
    server.close(async () => {
      await pool.end();
      console.log("HTTP server and DB pool closed");
      process.exit(0);
    });
  } catch (err) {
    console.error("Error during shutdown:", err.message);
    process.exit(1);
  }
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
