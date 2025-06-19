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
const chalk = require("chalk");
const Joi = require("joi");
const jwt = require("jsonwebtoken");
const WebSocket = require("ws");
const http = require("http");

const app = express();
const server = http.createServer(app);

// Configuration constants
const TOKEN_PATH = process.env.TOKEN_PATH || path.join(__dirname, "tokens.json");
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "viber2025";
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const NODE_ENV = process.env.NODE_ENV || "development";
const WEBSOCKET_PORT = process.env.WEBSOCKET_PORT || 3001;

console.log(chalk.blue.bold("🚀 Viber Token Gateway v2.1.0"));
console.log(chalk.gray(`Environment: ${NODE_ENV}`));

// Enhanced security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "ws:", "wss:"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: NODE_ENV === "production" ? process.env.ALLOWED_ORIGINS?.split(',') || false : "*",
  credentials: true
}));

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));
app.set("trust proxy", 1);

// Static file serving with enhanced security
app.use("/", express.static(path.join(__dirname, "public"), {
  extensions: ["html"],
  index: false,
  maxAge: NODE_ENV === "production" ? "1d" : "0",
  setHeaders: (res, filePath) => {
    if (filePath.endsWith(".json") && !filePath.includes("public")) {
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.status(403).end("Access denied");
    }
  },
}));

// Enhanced rate limiting with different tiers
const createLimiter = (windowMs, max, message, skipCondition = null) => rateLimit({
  windowMs,
  max,
  message: { error: message, retryAfter: Math.ceil(windowMs / 1000) },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    if (skipCondition && skipCondition(req)) return true;
    const isLocal = req.ip === "127.0.0.1" || req.ip === "::1" || req.ip === "::ffff:127.0.0.1";
    return NODE_ENV === "development" && isLocal;
  },
  keyGenerator: (req) => `${req.ip}-${req.headers['user-agent'] || 'unknown'}`,
});

// Multi-tier rate limiting
const apiLimiter = createLimiter(60 * 1000, 120, "Too many API requests");
const webhookLimiter = createLimiter(60 * 1000, 1000, "Too many webhook requests");
const adminLimiter = createLimiter(15 * 60 * 1000, 100, "Too many admin requests");
const strictLimiter = createLimiter(60 * 1000, 10, "Rate limit exceeded for sensitive operations");

app.use("/viber", apiLimiter);
app.use("/viber/webhook", webhookLimiter);
app.use("/admin", adminLimiter);

// Enhanced logging setup
const logDir = path.join(__dirname, "logs");
if (!fs.existsSync(logDir)) {
  try {
    fs.mkdirSync(logDir, { recursive: true });
    console.log(chalk.green("✓ Logs directory created"));
  } catch (err) {
    console.error(chalk.red("✗ Failed to create logs directory:"), err);
  }
}

// Custom Morgan format for better logging
morgan.token('body', (req) => {
  const body = req.body;
  if (body && typeof body === 'object') {
    const sanitized = { ...body };
    if (sanitized.real_token) sanitized.real_token = '***HIDDEN***';
    if (sanitized.password) sanitized.password = '***HIDDEN***';
    return JSON.stringify(sanitized);
  }
  return '-';
});

const accessLogStream = fs.createWriteStream(path.join(logDir, "access.log"), { flags: "a" });
app.use(morgan(":remote-addr - :remote-user [:date[clf]] \":method :url HTTP/:http-version\" :status :res[content-length] \":referrer\" \":user-agent\" :body", { 
  stream: accessLogStream,
  skip: (req, res) => NODE_ENV === "development" && (req.url === "/healthz" || req.url.startsWith("/admin/api/realtime"))
}));

// WebSocket for real-time updates
const wss = new WebSocket.Server({ server, path: '/admin/ws' });
const adminClients = new Set();

wss.on('connection', (ws, req) => {
  console.log(chalk.yellow('📡 Admin WebSocket connected'));
  adminClients.add(ws);
  
  ws.on('close', () => {
    adminClients.delete(ws);
    console.log(chalk.yellow('📡 Admin WebSocket disconnected'));
  });
  
  ws.on('error', (err) => {
    console.error(chalk.red('WebSocket error:'), err);
    adminClients.delete(ws);
  });
});

function broadcastToAdmins(data) {
  const message = JSON.stringify(data);
  adminClients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      try {
        client.send(message);
      } catch (err) {
        console.error(chalk.red('Failed to send WebSocket message:'), err);
        adminClients.delete(client);
      }
    }
  });
}

// Enhanced request logging with real-time updates
const requestLogFile = path.join(logDir, "requests.log");
function logRequest(entry) {
  try {
    const logEntry = {
      ...entry,
      timestamp: new Date().toISOString(),
      logId: crypto.randomBytes(4).toString("hex"),
      userAgent: entry.userAgent || "unknown",
      sessionId: entry.sessionId || null
    };
    
    const logLine = JSON.stringify(logEntry) + "\n";
    fs.appendFileSync(requestLogFile, logLine);
    
    // Broadcast to admin clients for real-time updates
    broadcastToAdmins({
      type: 'new_log',
      data: logEntry
    });
    
    // Log to console with colors based on type
    const colors = {
      viber_api_success: chalk.green,
      viber_api_error: chalk.red,
      invalid_token_attempt: chalk.yellow,
      webhook_received: chalk.blue,
      admin_login: chalk.magenta
    };
    
    const colorFn = colors[entry.type] || chalk.gray;
    console.log(colorFn(`[${entry.type.toUpperCase()}]`), logEntry.fakeToken || logEntry.uri || 'N/A');
    
  } catch (err) {
    console.error(chalk.red("Failed to write request log:"), err);
  }
}

// Input validation schemas
const tokenSchema = Joi.object({
  fakeToken: Joi.string().alphanum().min(8).max(50).required(),
  real_token: Joi.string().min(20).max(200).required(),
  uri: Joi.string().alphanum().min(3).max(50).required(),
  forwardUrl: Joi.string().uri().optional().allow('', null)
});

const fakeBotSchema = Joi.object({
  name: Joi.string().min(1).max(100).required(),
  uri: Joi.string().alphanum().min(3).max(50).required(),
  icon: Joi.string().uri().optional().allow(''),
  background: Joi.string().uri().optional().allow('')
});

// Token map management with file watching and caching
let tokenMapCache = null;
let lastTokenMapModified = null;
let tokenMapWatcher = null;

function loadTokenMap() {
  try {
    if (!fs.existsSync(TOKEN_PATH)) {
      const defaultMap = {};
      fs.writeFileSync(TOKEN_PATH, JSON.stringify(defaultMap, null, 2));
      console.log(chalk.yellow("⚠ Created default token map"));
      return defaultMap;
    }
    
    const stats = fs.statSync(TOKEN_PATH);
    if (!tokenMapCache || stats.mtimeMs !== lastTokenMapModified) {
      const raw = fs.readFileSync(TOKEN_PATH, "utf8");
      tokenMapCache = JSON.parse(raw);
      lastTokenMapModified = stats.mtimeMs;
      console.log(chalk.green(`✓ Token map ${tokenMapCache ? 'reloaded' : 'loaded'} - ${Object.keys(tokenMapCache).length} tokens`));
    }
    return tokenMapCache;
  } catch (e) {
    console.error(chalk.red("✗ Error loading token map:"), e);
    return {};
  }
}

function watchTokenMap() {
  if (tokenMapWatcher) {
    tokenMapWatcher.close();
  }
  
  try {
    tokenMapWatcher = fs.watchFile(TOKEN_PATH, { interval: 2000 }, () => {
      console.log(chalk.blue("📁 Token map file changed, reloading..."));
      const oldCount = Object.keys(tokenMapCache || {}).length;
      tokenMapCache = null;
      const newMap = loadTokenMap();
      const newCount = Object.keys(newMap).length;
      
      broadcastToAdmins({
        type: 'token_map_updated',
        data: { oldCount, newCount, timestamp: new Date().toISOString() }
      });
    });
  } catch (err) {
    console.warn(chalk.yellow("⚠ Could not watch token map file:"), err);
  }
}

loadTokenMap();
watchTokenMap();

// Enhanced Viber API forwarding with circuit breaker pattern
const circuitBreaker = {
  failures: new Map(),
  threshold: 5,
  timeout: 30000,
  
  canExecute(key) {
    const failure = this.failures.get(key);
    if (!failure) return true;
    
    if (failure.count >= this.threshold) {
      if (Date.now() - failure.lastFailure < this.timeout) {
        return false;
      } else {
        this.failures.delete(key);
        return true;
      }
    }
    return true;
  },
  
  recordSuccess(key) {
    this.failures.delete(key);
  },
  
  recordFailure(key) {
    const failure = this.failures.get(key) || { count: 0, lastFailure: 0 };
    failure.count++;
    failure.lastFailure = Date.now();
    this.failures.set(key, failure);
  }
};

async function forwardViberAPI(realToken, endpoint, body = {}, retries = 3) {
  const circuitKey = `${realToken}-${endpoint}`;
  
  if (!circuitBreaker.canExecute(circuitKey)) {
    throw new Error('Circuit breaker open - too many failures');
  }
  
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
            "User-Agent": "ViberTokenGateway/2.1.0"
          },
          timeout: 10000,
          validateStatus: (status) => status < 500 || status === 429
        }
      );
      
      circuitBreaker.recordSuccess(circuitKey);
      return response;
    } catch (err) {
      lastError = err;
      circuitBreaker.recordFailure(circuitKey);
      
      if (attempt < retries - 1) {
        const isRetryable = err.code === 'ECONNRESET' || 
                           err.code === 'ETIMEDOUT' ||
                           err.code === 'ENOTFOUND' ||
                           (err.response && err.response.status >= 500);
        
        if (isRetryable) {
          const delay = Math.min(Math.pow(2, attempt) * 1000, 5000);
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }
      }
      break;
    }
  }
  
  throw lastError;
}

// JWT-based admin authentication
function generateAdminToken(username) {
  return jwt.sign(
    { username, role: 'admin', iat: Date.now() },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
}

function verifyAdminToken(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.cookies?.adminToken;
  
  if (!token) {
    return res.status(401).json({ error: 'No authentication token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Basic Auth middleware for admin routes (fallback)
const adminAuth = basicAuth({
  users: { [ADMIN_USERNAME]: ADMIN_PASSWORD },
  challenge: true,
  unauthorizedResponse: (req) => ({
    error: "Unauthorized access to admin panel",
    loginUrl: "/admin/login"
  })
});

// Admin login endpoint for JWT
app.post("/admin/login", strictLimiter, (req, res) => {
  const { username, password } = req.body;
  
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const token = generateAdminToken(username);
    
    logRequest({
      type: "admin_login_success",
      ip: req.ip,
      username,
      userAgent: req.headers["user-agent"]
    });
    
    res.cookie('adminToken', token, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    res.json({ 
      success: true, 
      token,
      expiresIn: '24h'
    });
  } else {
    logRequest({
      type: "admin_login_failed",
      ip: req.ip,
      username,
      userAgent: req.headers["user-agent"]
    });
    
    res.status(401).json({ 
      error: "Invalid credentials",
      attempts: req.rateLimit?.totalHits || 1
    });
  }
});

// Apply authentication to admin routes
app.use("/admin/api", verifyAdminToken);
app.use("/admin/ui", adminAuth); // Fallback to basic auth for UI

// Enhanced health check with detailed metrics
app.get("/healthz", (req, res) => {
  const tokenMap = loadTokenMap();
  const health = {
    status: "ok",
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    version: "2.1.0",
    environment: NODE_ENV,
    metrics: {
      memory: process.memoryUsage(),
      tokenCount: Object.keys(tokenMap).length,
      activeWebSockets: adminClients.size,
      circuitBreakerFailures: circuitBreaker.failures.size
    },
    features: {
      realTimeUpdates: true,
      circuitBreaker: true,
      rateLimiting: true,
      webhookForwarding: true
    }
  };
  
  res.json(health);
});

// Viber API endpoints with enhanced error handling
const VIBER_ENDPOINTS = [
  "send_message", 
  "get_info", 
  "transfer_owner", 
  "add_member",
  "get_account_info",
  "get_user_details",
  "get_online",
  "broadcast_message",
  "remove_member",
  "get_members"
];

VIBER_ENDPOINTS.forEach((endpoint) => {
  app.post(`/viber/${endpoint}`, async (req, res) => {
    const fakeToken = req.headers["x-fake-token"];
    const userAgent = req.headers["user-agent"];
    const sessionId = req.headers["x-session-id"];
    
    if (!fakeToken) {
      return res.status(401).json({ 
        error: "Missing X-Fake-Token header",
        code: "MISSING_TOKEN",
        hint: "Add 'X-Fake-Token: YOUR_FAKE_TOKEN' header"
      });
    }

    // Validate fake token format
    if (!/^[A-Z0-9_]{8,50}$/.test(fakeToken)) {
      return res.status(400).json({
        error: "Invalid fake token format",
        code: "INVALID_TOKEN_FORMAT"
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
        userAgent,
        sessionId
      });
      
      return res.status(403).json({ 
        error: "Invalid or expired token",
        code: "INVALID_TOKEN",
        validTokens: Object.keys(tokenMap).length
      });
    }

    try {
      const startTime = Date.now();
      const response = await forwardViberAPI(profile.real_token, endpoint, req.body);
      const duration = Date.now() - startTime;
      
      logRequest({
        type: "viber_api_success",
        ip: req.ip,
        fakeToken,
        endpoint,
        status: response.status,
        duration,
        responseSize: JSON.stringify(response.data).length,
        userAgent,
        sessionId
      });
      
      // Update last used timestamp
      profile.lastUsed = new Date().toISOString();
      profile.usage = (profile.usage || 0) + 1;
      tokenMap[fakeToken] = profile;
      
      try {
        fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokenMap, null, 2));
      } catch (err) {
        console.warn(chalk.yellow("⚠ Failed to update lastUsed timestamp:"), err);
      }
      
      // Add performance headers
      res.setHeader('X-Response-Time', `${duration}ms`);
      res.setHeader('X-Gateway-Version', '2.1.0');
      
      res.status(response.status).json(response.data);
      
    } catch (err) {
      const errorData = {
        type: "viber_api_error",
        ip: req.ip,
        fakeToken,
        endpoint,
        error: err.message,
        status: err.response?.status || 500,
        userAgent,
        sessionId
      };
      
      logRequest(errorData);
      
      const errorResponse = {
        error: "Viber API Error",
        code: "VIBER_API_ERROR",
        message: err.message,
        status: err.response?.status || 500,
        endpoint,
        timestamp: new Date().toISOString()
      };
      
      if (NODE_ENV === "development") {
        errorResponse.debug = {
          response: err.response?.data,
          stack: err.stack?.split('\n').slice(0, 5)
        };
      }
      
      res.status(errorData.status).json(errorResponse);
    }
  });
});

// Enhanced fake bot info management
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
    console.error(chalk.red("Failed to load fake bots:"), e);
    return {};
  }
}

function saveFakeBots(data) {
  try {
    fs.writeFileSync(fakeBotFile, JSON.stringify(data, null, 2), "utf8");
    return true;
  } catch (e) {
    console.error(chalk.red("Failed to save fake bots:"), e);
    return false;
  }
}

// Enhanced fake bot info endpoints
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
      code: "INFO_NOT_FOUND",
      availableTokens: Object.keys(fakeBots)
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

app.post("/viber/fake_info", (req, res) => {
  const fakeToken = req.headers["x-fake-token"];
  
  if (!fakeToken) {
    return res.status(400).json({ 
      error: "Missing X-Fake-Token header",
      code: "MISSING_TOKEN"
    });
  }

  // Validate input
  const { error, value } = fakeBotSchema.validate(req.body);
  if (error) {
    return res.status(400).json({
      error: "Validation failed",
      code: "VALIDATION_ERROR",
      details: error.details.map(d => d.message)
    });
  }

  const fakeBots = loadFakeBots();
  const updatedInfo = {
    ...value,
    updatedAt: new Date().toISOString(),
    version: "2.1.0"
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

// Enhanced admin API endpoints
app.get("/admin/api/dashboard-stats", (req, res) => {
  try {
    const tokenMap = loadTokenMap();
    const fakeBots = loadFakeBots();
    
    // Calculate usage statistics
    const tokens = Object.entries(tokenMap);
    const totalUsage = tokens.reduce((sum, [, profile]) => sum + (profile.usage || 0), 0);
    const activeTokens = tokens.filter(([, profile]) => profile.lastUsed).length;
    
    // Recent activity (last 24 hours)
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentlyUsed = tokens.filter(([, profile]) => 
      profile.las
