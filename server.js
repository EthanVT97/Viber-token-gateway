require("dotenv").config();
const express = require("express");
const axios = require("axios");
const rateLimit = require("express-rate-limit");
const basicAuth = require("express-basic-auth");
const fs = require("fs");
const path = require("path");
const helmet = require("helmet");
const morgan = require("morgan");
const crypto = require("crypto");
const cors = require("cors");

const app = express();

// Configuration constants
const TOKEN_PATH = process.env.TOKEN_PATH || path.join(__dirname, "tokens.json");
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "viber2025";
const NODE_ENV = process.env.NODE_ENV || "development";

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: NODE_ENV === "production" ? false : "*",
  credentials: true
}));

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));
app.set("trust proxy", 1);

// Static file serving with proper security
app.use("/", express.static(path.join(__dirname, "public"), {
  extensions: ["html"],
  index: false,
  maxAge: NODE_ENV === "production" ? "1d" : "0",
  setHeaders: (res, filePath) => {
    if (filePath.endsWith(".json")) {
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.status(403).end("Access denied");
    }
  },
}));

// Enhanced rate limiting with IP tracking
const createLimiter = (windowMs, max, message) => rateLimit({
  windowMs,
  max,
  message: { error: message },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    const isLocal = req.ip === "127.0.0.1" || req.ip === "::1" || req.ip === "::ffff:127.0.0.1";
    return NODE_ENV === "development" && isLocal;
  },
});

// Different limits for different endpoints
const apiLimiter = createLimiter(60 * 1000, 100, "Too many API requests");
const webhookLimiter = createLimiter(60 * 1000, 500, "Too many webhook requests");
const adminLimiter = createLimiter(15 * 60 * 1000, 50, "Too many admin requests");

app.use("/viber", apiLimiter);
app.use("/viber/webhook", webhookLimiter);
app.use("/admin", adminLimiter);

// Logging setup with proper error handling
const logDir = path.join(__dirname, "logs");
if (!fs.existsSync(logDir)) {
  try {
    fs.mkdirSync(logDir, { recursive: true });
  } catch (err) {
    console.error("Failed to create logs directory:", err);
  }
}

const accessLogStream = fs.createWriteStream(path.join(logDir, "access.log"), { flags: "a" });
app.use(morgan("combined", { 
  stream: accessLogStream,
  skip: (req, res) => NODE_ENV === "development" && req.url === "/healthz"
}));

const requestLogFile = path.join(logDir, "requests.log");
function logRequest(entry) {
  try {
    const logEntry = {
      ...entry,
      timestamp: new Date().toISOString(),
      logId: crypto.randomBytes(4).toString("hex"),
      userAgent: entry.userAgent || "unknown"
    };
    
    const logLine = JSON.stringify(logEntry) + "\n";
    fs.appendFileSync(requestLogFile, logLine);
  } catch (err) {
    console.error("Failed to write request log:", err);
  }
}

// Token map management with file watching
let tokenMapCache = null;
let lastTokenMapModified = null;
let tokenMapWatcher = null;

function loadTokenMap() {
  try {
    if (!fs.existsSync(TOKEN_PATH)) {
      // Create default token map if it doesn't exist
      const defaultMap = {};
      fs.writeFileSync(TOKEN_PATH, JSON.stringify(defaultMap, null, 2));
      return defaultMap;
    }
    
    const stats = fs.statSync(TOKEN_PATH);
    if (!tokenMapCache || stats.mtimeMs !== lastTokenMapModified) {
      const raw = fs.readFileSync(TOKEN_PATH, "utf8");
      tokenMapCache = JSON.parse(raw);
      lastTokenMapModified = stats.mtimeMs;
      console.log(`Token map ${tokenMapCache ? 'reloaded' : 'loaded'} at ${new Date().toISOString()}`);
    }
    return tokenMapCache;
  } catch (e) {
    console.error("Error loading token map:", e);
    return {};
  }
}

// Watch for token map file changes
function watchTokenMap() {
  if (tokenMapWatcher) {
    tokenMapWatcher.close();
  }
  
  try {
    tokenMapWatcher = fs.watchFile(TOKEN_PATH, { interval: 1000 }, () => {
      console.log("Token map file changed, reloading...");
      tokenMapCache = null; // Force reload
      loadTokenMap();
    });
  } catch (err) {
    console.warn("Could not watch token map file:", err);
  }
}

// Initialize token map and watcher
loadTokenMap();
watchTokenMap();

// Enhanced Viber API forwarding with better error handling
async function forwardViberAPI(realToken, endpoint, body = {}, retries = 3) {
  let lastError;
  
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const response = await axios.post(
        `https://chatapi.viber.com/pa/${endpoint}`,
        body,
        {
          headers: {
            "X-Viber-Auth-Token": realToken,
            "Content-Type": "application/json",
            "User-Agent": "ViberTokenGateway/2.0.0"
          },
          timeout: 8000,
          validateStatus: (status) => status < 500 || status === 429
        }
      );
      
      return response;
    } catch (err) {
      lastError = err;
      
      if (attempt < retries - 1) {
        const isRetryable = err.code === 'ECONNRESET' || 
                           err.code === 'ETIMEDOUT' ||
                           (err.response && err.response.status >= 500);
        
        if (isRetryable) {
          const delay = Math.pow(2, attempt) * 1000; // Exponential backoff
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }
      }
      break;
    }
  }
  
  throw lastError;
}

// Basic Auth middleware for admin routes
const adminAuth = basicAuth({
  users: { [ADMIN_USERNAME]: ADMIN_PASSWORD },
  challenge: true,
  unauthorizedResponse: (req) => {
    return { error: "Unauthorized access to admin panel" };
  }
});

app.use("/admin", adminAuth);

// Health check endpoint with detailed info
app.get("/healthz", (req, res) => {
  const health = {
    status: "ok",
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    memory: process.memoryUsage(),
    version: "2.0.0",
    environment: NODE_ENV,
    tokenMapSize: Object.keys(loadTokenMap()).length
  };
  
  res.json(health);
});

// Viber API proxy endpoints with enhanced logging
const VIBER_ENDPOINTS = [
  "send_message", 
  "get_info", 
  "transfer_owner", 
  "add_member",
  "get_account_info",
  "get_user_details",
  "get_online",
  "broadcast_message"
];

VIBER_ENDPOINTS.forEach((endpoint) => {
  app.post(`/viber/${endpoint}`, async (req, res) => {
    const fakeToken = req.headers["x-fake-token"];
    const userAgent = req.headers["user-agent"];
    
    if (!fakeToken) {
      return res.status(401).json({ 
        error: "Missing X-Fake-Token header",
        code: "MISSING_TOKEN"
      });
    }

    const tokenMap = loadTokenMap();
    const profile = tokenMap[fakeToken];
    
    if (!profile || !profile.real_token) {
      logRequest({
        type: "invalid_token_attempt",
        ip: req.ip,
        fakeToken,
        endpoint,
        userAgent
      });
      
      return res.status(403).json({ 
        error: "Invalid or expired token",
        code: "INVALID_TOKEN"
      });
    }

    try {
      const response = await forwardViberAPI(profile.real_token, endpoint, req.body);
      
      logRequest({
        type: "viber_api_success",
        ip: req.ip,
        fakeToken,
        endpoint,
        status: response.status,
        responseSize: JSON.stringify(response.data).length,
        userAgent
      });
      
      // Update last used timestamp
      profile.lastUsed = new Date().toISOString();
      tokenMap[fakeToken] = profile;
      
      try {
        fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokenMap, null, 2));
      } catch (err) {
        console.warn("Failed to update lastUsed timestamp:", err);
      }
      
      res.status(response.status).json(response.data);
      
    } catch (err) {
      const errorData = {
        type: "viber_api_error",
        ip: req.ip,
        fakeToken,
        endpoint,
        error: err.message,
        status: err.response?.status || 500,
        userAgent
      };
      
      logRequest(errorData);
      
      const errorResponse = {
        error: "Viber API Error",
        code: "VIBER_API_ERROR",
        message: err.message,
        status: err.response?.status || 500
      };
      
      if (NODE_ENV === "development") {
        errorResponse.debug = {
          response: err.response?.data,
          stack: err.stack
        };
      }
      
      res.status(errorData.status).json(errorResponse);
    }
  });
});

// Fake bot info management
const fakeBotFile = path.join(__dirname, "fake_bots.json");

function loadFakeBots() {
  try {
    if (!fs.existsSync(fakeBotFile)) {
      const defaultData = {};
      fs.writeFileSync(fakeBotFile, JSON.stringify(defaultData, null, 2));
      return defaultData;
    }
    return JSON.parse(fs.readFileSync(fakeBotFile, "utf8"));
  } catch (e) {
    console.error("Failed to load fake bots:", e);
    return {};
  }
}

function saveFakeBots(data) {
  try {
    fs.writeFileSync(fakeBotFile, JSON.stringify(data, null, 2), "utf8");
    return true;
  } catch (e) {
    console.error("Failed to save fake bots:", e);
    return false;
  }
}

// Get fake bot info
app.get("/viber/fake_info", (req, res) => {
  const fakeToken = req.headers["x-fake-token"];
  
  if (!fakeToken) {
    return res.status(400).json({ 
      error: "Missing X-Fake-Token header",
      code: "MISSING_TOKEN"
    });
  }

  const fakeBots = loadFakeBots();
  const info = fakeBots[fakeToken];
  
  if (!info) {
    return res.status(404).json({ 
      error: "No fake bot info found for this token",
      code: "INFO_NOT_FOUND"
    });
  }

  logRequest({
    type: "fake_info_retrieved",
    ip: req.ip,
    fakeToken,
    userAgent: req.headers["user-agent"]
  });

  res.json({ 
    status: "ok", 
    info,
    timestamp: new Date().toISOString()
  });
});

// Update fake bot info
app.post("/viber/fake_info", (req, res) => {
  const fakeToken = req.headers["x-fake-token"];
  const { name, uri, icon, background } = req.body;
  
  if (!fakeToken) {
    return res.status(400).json({ 
      error: "Missing X-Fake-Token header",
      code: "MISSING_TOKEN"
    });
  }

  if (!name || !uri) {
    return res.status(400).json({ 
      error: "Missing required fields: name and uri are required",
      code: "MISSING_FIELDS"
    });
  }

  const fakeBots = loadFakeBots();
  const updatedInfo = {
    name: name.trim(),
    uri: uri.trim(),
    icon: icon || "",
    background: background || "",
    updatedAt: new Date().toISOString()
  };

  fakeBots[fakeToken] = updatedInfo;
  
  if (!saveFakeBots(fakeBots)) {
    return res.status(500).json({
      error: "Failed to save fake bot info",
      code: "SAVE_ERROR"
    });
  }

  logRequest({
    type: "fake_info_updated",
    ip: req.ip,
    fakeToken,
    info: updatedInfo,
    userAgent: req.headers["user-agent"]
  });

  res.json({ 
    status: "ok", 
    message: "Fake bot info updated successfully",
    info: updatedInfo
  });
});

// Admin API endpoints
app.get("/admin/api/token-map", (req, res) => {
  const tokenMap = loadTokenMap();
  
  // Sanitize real tokens for security
  const sanitizedMap = {};
  Object.keys(tokenMap).forEach(fakeToken => {
    sanitizedMap[fakeToken] = {
      ...tokenMap[fakeToken],
      real_token: tokenMap[fakeToken].real_token ? "***HIDDEN***" : null
    };
  });
  
  res.json(sanitizedMap);
});

app.get("/admin/api/logs", (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
  const searchToken = req.query.token;
  const logType = req.query.type;
  
  try {
    if (!fs.existsSync(requestLogFile)) {
      return res.json([]);
    }
    
    const logData = fs.readFileSync(requestLogFile, "utf8").trim();
    if (!logData) {
      return res.json([]);
    }
    
    let logs = logData.split("\n").reverse();
    
    // Apply filters
    if (searchToken) {
      logs = logs.filter(line => line.includes(`"fakeToken":"${searchToken}"`));
    }
    
    if (logType) {
      logs = logs.filter(line => line.includes(`"type":"${logType}"`));
    }
    
    const parsedLogs = logs.slice(0, limit).map(line => {
      try {
        return JSON.parse(line);
      } catch {
        return { error: "Invalid log line", raw: line };
      }
    });
    
    res.json(parsedLogs);
  } catch (err) {
    console.error("Failed to read logs:", err);
    res.status(500).json({ error: "Failed to read logs", code: "LOG_READ_ERROR" });
  }
});

app.post("/admin/api/add-token", (req, res) => {
  const { fakeToken, real_token, uri, forwardUrl } = req.body;
  
  if (!fakeToken || !real_token || !uri) {
    return res.status(400).json({ 
      error: "Missing required parameters: fakeToken, real_token, and uri are required",
      code: "MISSING_PARAMETERS"
    });
  }
  
  try {
    const tokenMap = loadTokenMap();
    
    // Check if fake token already exists
    if (tokenMap[fakeToken]) {
      return res.status(409).json({
        error: "Fake token already exists",
        code: "TOKEN_EXISTS"
      });
    }
    
    tokenMap[fakeToken] = {
      real_token: real_token.trim(),
      uri: uri.trim(),
      forwardUrl: forwardUrl ? forwardUrl.trim() : null,
      createdAt: new Date().toISOString(),
      lastUsed: null
    };
    
    fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokenMap, null, 2), "utf8");
    tokenMapCache = null; // Force reload
    
    logRequest({
      type: "token_added",
      ip: req.ip,
      fakeToken,
      uri: uri.trim(),
      userAgent: req.headers["user-agent"]
    });
    
    res.json({ 
      status: "ok", 
      message: "Token added successfully",
      token: fakeToken
    });
  } catch (e) {
    console.error("Failed to add token:", e);
    res.status(500).json({ 
      error: "Failed to write token map",
      code: "WRITE_ERROR"
    });
  }
});

app.delete("/admin/api/delete-token", (req, res) => {
  const { fakeToken } = req.body;
  
  if (!fakeToken) {
    return res.status(400).json({
      error: "Missing fakeToken parameter",
      code: "MISSING_PARAMETER"
    });
  }
  
  try {
    const tokenMap = loadTokenMap();
    
    if (!tokenMap[fakeToken]) {
      return res.status(404).json({
        error: "Token not found",
        code: "TOKEN_NOT_FOUND"
      });
    }
    
    delete tokenMap[fakeToken];
    fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokenMap, null, 2), "utf8");
    tokenMapCache = null; // Force reload
    
    logRequest({
      type: "token_deleted",
      ip: req.ip,
      fakeToken,
      userAgent: req.headers["user-agent"]
    });
    
    res.json({
      status: "ok",
      message: "Token deleted successfully"
    });
  } catch (e) {
    console.error("Failed to delete token:", e);
    res.status(500).json({
      error: "Failed to update token map",
      code: "DELETE_ERROR"
    });
  }
});

// Webhook endpoint with enhanced security
app.post("/viber/webhook/:uri", express.raw({ type: "*/*", limit: "50kb" }), async (req, res) => {
  const uri = req.params.uri;
  const signature = req.headers["x-viber-content-signature"];
  
  if (!signature) {
    return res.status(400).json({ error: "Missing signature header" });
  }
  
  const tokenMap = loadTokenMap();
  const fakeToken = Object.keys(tokenMap).find(token => tokenMap[token].uri === uri);
  
  if (!fakeToken) {
    logRequest({
      type: "webhook_unknown_uri",
      uri,
      ip: req.ip,
      userAgent: req.headers["user-agent"]
    });
    return res.status(404).json({ error: "Unknown URI" });
  }

  const realToken = tokenMap[fakeToken].real_token;
  
  // Verify signature
  const computedSignature = crypto
    .createHmac("sha256", realToken)
    .update(req.body)
    .digest("base64");
    
  if (signature !== computedSignature) {
    logRequest({
      type: "webhook_invalid_signature",
      fakeToken,
      uri,
      ip: req.ip,
      userAgent: req.headers["user-agent"]
    });
    return res.status(403).json({ error: "Invalid signature" });
  }

  let payload;
  try {
    payload = JSON.parse(req.body.toString());
  } catch (err) {
    logRequest({
      type: "webhook_invalid_json",
      fakeToken,
      uri,
      ip: req.ip,
      error: err.message,
      userAgent: req.headers["user-agent"]
    });
    return res.status(400).json({ error: "Invalid JSON payload" });
  }

  logRequest({
    type: "webhook_received",
    fakeToken,
    uri,
    ip: req.ip,
    event: payload.event,
    userAgent: req.headers["user-agent"]
  });

  // Forward to external endpoint if configured
  const forwardUrl = tokenMap[fakeToken].forwardUrl;
  if (forwardUrl) {
    const maxRetries = 3;
    let forwarded = false;
    let lastError = null;

    for (let attempt = 0; attempt < maxRetries && !forwarded; attempt++) {
      try {
        await axios.post(forwardUrl, payload, {
          headers: {
            "Content-Type": "application/json",
            "X-Forwarded-For": req.ip,
            "X-Fake-Token": fakeToken,
            "X-Original-URI": uri,
            "User-Agent": "ViberTokenGateway/2.0.0"
          },
          timeout: 8000,
        });
        forwarded = true;
      } catch (err) {
        lastError = err;
        if (attempt < maxRetries - 1) {
          await new Promise(resolve => setTimeout(resolve, 1000 * Math.pow(2, attempt)));
        }
      }
    }

    if (!forwarded) {
      logRequest({
        type: "webhook_forward_failed",
        fakeToken,
        uri,
        ip: req.ip,
        error: lastError?.message || "Unknown error",
        forwardUrl,
        userAgent: req.headers["user-agent"]
      });
      
      return res.status(500).json({ 
        error: "Failed to forward webhook event",
        code: "FORWARD_ERROR"
      });
    }
  }

  res.status(200).json({ status: "ok", timestamp: new Date().toISOString() });
});

// Admin UI route
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// 404 handler
app.use("*", (req, res) => {
  res.status(404).json({ 
    error: "Endpoint not found",
    code: "NOT_FOUND",
    path: req.originalUrl
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  
  logRequest({
    type: "server_error",
    ip: req.ip,
    error: err.message,
    stack: err.stack,
    url: req.originalUrl,
    userAgent: req.headers["user-agent"]
  });
  
  res.status(500).json({
    error: "Internal server error",
    code: "INTERNAL_ERROR",
    ...(NODE_ENV === "development" && { debug: err.message })
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  if (tokenMapWatcher) {
    tokenMapWatcher.close();
  }
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  if (tokenMapWatcher) {
    tokenMapWatcher.close();
  }
  process.exit(0);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Viber Token Gateway v2.0.0 running on port ${PORT}`);
  console.log(`📊 Environment: ${NODE_ENV}`);
  console.log(`🔧 Admin panel: http://localhost:${PORT}/admin`);
  console.log(`💾 Token map: ${Object.keys(loadTokenMap()).length} tokens loaded`);
});
