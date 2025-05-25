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

const app = express();

// 1. Enhanced Security Configurations
app.use(helmet());
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));
app.set("trust proxy", 1);

// 2. Secure Static File Serving
app.use("/", express.static(path.join(__dirname, "public"), {
  extensions: ["html"],
  index: false,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith(".json")) {
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.status(403).end("Access denied");
    }
  }
}));

// 3. Rate Limiting with Enhanced Config
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: "Too many requests, please try again later." },
  skip: (req) => req.ip === "127.0.0.1" // Skip for localhost
});

app.use(apiLimiter);

// 4. Dynamic Token Reloading System
let tokenMapCache = null;
let lastTokenMapModified = null;

function loadTokenMap() {
  const tokenPath = path.join(__dirname, "tokens.json");
  try {
    const stats = fs.statSync(tokenPath);
    
    if (!tokenMapCache || stats.mtimeMs !== lastTokenMapModified) {
      const raw = fs.readFileSync(tokenPath, "utf8");
      tokenMapCache = JSON.parse(raw);
      lastTokenMapModified = stats.mtimeMs;
      console.log("Token map reloaded at", new Date().toISOString());
    }
    return tokenMapCache;
  } catch (e) {
    console.error("Failed to load tokens.json:", e);
    return {};
  }
}

// 5. Enhanced Logging System
const logDir = path.join(__dirname, "logs");
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir);

const accessLogStream = fs.createWriteStream(
  path.join(logDir, "access.log"), 
  { flags: "a" }
);
app.use(morgan("combined", { stream: accessLogStream }));

const requestLogStream = fs.createWriteStream(
  path.join(logDir, "requests.log"),
  { flags: "a" }
);

function logRequest(entry) {
  const logLine = JSON.stringify({
    ...entry,
    timestamp: new Date().toISOString(),
    logId: crypto.randomBytes(4).toString("hex")
  }) + "\n";
  requestLogStream.write(logLine);
}

// 6. Viber API Proxy Function with Retry Logic
async function forwardViberAPI(realToken, endpoint, body = {}, retries = 3) {
  try {
    const viberRes = await axios.post(
      `https://chatapi.viber.com/pa/${endpoint}`,
      body,
      {
        headers: {
          "X-Viber-Auth-Token": realToken,
          "Content-Type": "application/json",
        },
        timeout: 5000
      }
    );
    return viberRes;
  } catch (err) {
    if (retries > 0 && err.response?.status >= 500) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      return forwardViberAPI(realToken, endpoint, body, retries - 1);
    }
    throw err;
  }
}

// 7. Admin Authentication with Enhanced Security
app.use("/admin", basicAuth({
  users: { 
    [process.env.ADMIN_USERNAME || "admin"]: process.env.ADMIN_PASSWORD || crypto.randomBytes(8).toString("hex")
  },
  challenge: true,
  unauthorizedResponse: { error: "Unauthorized" },
  authorizeAsync: true,
  authorizer: (username, password, cb) => {
    const userMatches = basicAuth.safeCompare(username, process.env.ADMIN_USERNAME || "admin");
    const passwordMatches = basicAuth.safeCompare(password, process.env.ADMIN_PASSWORD || "");
    cb(null, userMatches && passwordMatches);
  }
}));

// 8. Health Check Endpoint
app.get("/healthz", (req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// 9. Viber Proxy Endpoints with Enhanced Error Handling
const viberEndpoints = ["send_message", "get_info", "transfer_owner", "add_member"];
viberEndpoints.forEach((endpoint) => {
  app.post(`/viber/${endpoint}`, async (req, res) => {
    const fakeToken = req.headers["x-fake-token"];
    if (!fakeToken) return res.status(401).json({ error: "Missing X-Fake-Token header" });

    const map = loadTokenMap();
    const profile = map[fakeToken];
    if (!profile) return res.status(403).json({ error: "Invalid token" });

    try {
      const viberRes = await forwardViberAPI(profile.real_token, endpoint, req.body);
      
      logRequest({
        type: "viber_api",
        ip: req.ip,
        fakeToken: fakeToken,
        endpoint: `/viber/${endpoint}`,
        status: viberRes.status,
        response: viberRes.data
      });

      res.status(viberRes.status).json(viberRes.data);
    } catch (err) {
      const errorData = {
        type: "viber_api_error",
        ip: req.ip,
        fakeToken: fakeToken,
        endpoint: `/viber/${endpoint}`,
        error: err.message,
        status: err.response?.status || 500,
        response: err.response?.data
      };

      logRequest(errorData);
      res.status(errorData.status).json({
        error: "Viber API Error",
        detail: err.message,
        response: err.response?.data
      });
    }
  });
});

// 10. Enhanced Fake Bot Management
const fakeBotFile = path.join(__dirname, "fake_bots.json");

function loadFakeBots() {
  try {
    if (!fs.existsSync(fakeBotFile)) return {};
    return JSON.parse(fs.readFileSync(fakeBotFile, "utf8"));
  } catch (e) {
    console.error("Failed to load fake bots:", e);
    return {};
  }
}

function saveFakeBots(data) {
  fs.writeFileSync(fakeBotFile, JSON.stringify(data, null, 2), "utf8");
}

app.get("/viber/fake_info", (req, res) => {
  const fakeToken = req.headers["x-fake-token"];
  if (!fakeToken) return res.status(400).json({ error: "Missing fake token" });

  try {
    const info = loadFakeBots()[fakeToken];
    if (!info) return res.status(404).json({ error: "No fake bot info found" });

    res.json({ status: "ok", info });
  } catch (e) {
    res.status(500).json({ error: "Failed to read fake bot info" });
  }
});

app.post("/viber/fake_info", (req, res) => {
  const fakeToken = req.headers["x-fake-token"];
  const { name, uri, icon, background } = req.body;
  if (!fakeToken) return res.status(400).json({ error: "Missing fake token" });

  try {
    const data = loadFakeBots();
    data[fakeToken] = { name, uri, icon, background, updatedAt: new Date().toISOString() };
    saveFakeBots(data);

    res.json({ status: "ok", message: "Fake bot info updated" });
  } catch (e) {
    res.status(500).json({ error: "Failed to update fake bot info" });
  }
});

// 11. Enhanced Admin API Endpoints
app.get("/admin/api/token-map", (req, res) => {
  res.json(loadTokenMap());
});

app.get("/admin/api/logs", (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
  const searchToken = req.query.token;

  try {
    const logData = fs.readFileSync(path.join(logDir, "requests.log"), "utf8");
    let logs = logData.trim().split("\n").reverse();

    if (searchToken) {
      logs = logs.filter(line => line.includes(`"fakeToken":"${searchToken}"`));
    }

    const parsedLogs = logs.slice(0, limit).map(line => {
      try {
        return JSON.parse(line);
      } catch {
        return { error: "Invalid log line" };
      }
    });

    res.json(parsedLogs);
  } catch (err) {
    res.status(500).json({ error: "Failed to read logs" });
  }
});

app.post("/admin/api/add-token", (req, res) => {
  const { fakeToken, real_token, uri } = req.body;
  if (!fakeToken || !real_token || !uri) {
    return res.status(400).json({ error: "Missing parameters" });
  }

  try {
    const map = loadTokenMap();
    map[fakeToken] = { 
      real_token, 
      uri,
      createdAt: new Date().toISOString(),
      lastUsed: null
    };
    
    fs.writeFileSync(
      path.join(__dirname, "tokens.json"),
      JSON.stringify(map, null, 2),
      "utf8"
    );
    
    tokenMapCache = null; // Clear cache
    res.json({ status: "ok", message: "Token added" });
  } catch (e) {
    res.status(500).json({ error: "Failed to write token map" });
  }
});

// 12. Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  logRequest({
    type: "server_error",
    error: err.message,
    stack: process.env.NODE_ENV === "development" ? err.stack : undefined
  });
  res.status(500).json({ error: "Internal Server Error" });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Viber Token Gateway running on port ${PORT}`);
  console.log(`Admin panel: http://localhost:${PORT}/admin`);
  console.log(`Health check: http://localhost:${PORT}/healthz`);
});
