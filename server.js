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

const TOKEN_PATH = process.env.TOKEN_PATH || path.join(__dirname, "tokens.json");
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "viber2025";

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));
app.set("trust proxy", 1);

app.get("/", (req, res) => {
  res.send("Viber Token Gateway is running.");
});

app.use("/", express.static(path.join(__dirname, "public"), {
  extensions: ["html"],
  index: false,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith(".json")) {
      res.setHeader("X-Content-Type-Options", "nosniff");
      return res.status(403).end("Access denied");
    }
  }
}));

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: "Too many requests, please try again later." },
  skip: req => req.ip === "127.0.0.1",
});
app.use(apiLimiter);

const logDir = path.join(__dirname, "logs");
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir);
const accessLogStream = fs.createWriteStream(path.join(logDir, "access.log"), { flags: "a" });
app.use(morgan("combined", { stream: accessLogStream }));

const requestLogStream = fs.createWriteStream(path.join(logDir, "requests.log"), { flags: "a" });
function logRequest(entry) {
  requestLogStream.write(JSON.stringify({ ...entry, timestamp: new Date().toISOString(), logId: crypto.randomBytes(4).toString("hex") }) + "\n");
}

let tokenMapCache = null;
let lastTokenMapModified = null;
function loadTokenMap() {
  try {
    if (!fs.existsSync(TOKEN_PATH)) return {};
    const stats = fs.statSync(TOKEN_PATH);
    if (!tokenMapCache || stats.mtimeMs !== lastTokenMapModified) {
      const raw = fs.readFileSync(TOKEN_PATH, "utf8");
      tokenMapCache = JSON.parse(raw);
      lastTokenMapModified = stats.mtimeMs;
      console.log("Token map reloaded at", new Date().toISOString());
    }
    return tokenMapCache;
  } catch (e) {
    console.error("Error loading token map:", e);
    return {};
  }
}

async function forwardViberAPI(realToken, endpoint, body = {}, retries = 3) {
  try {
    return await axios.post(`https://chatapi.viber.com/pa/${endpoint}`, body, {
      headers: {
        "X-Viber-Auth-Token": realToken,
        "Content-Type": "application/json"
      },
      timeout: 5000
    });
  } catch (err) {
    if (retries > 0 && err.response?.status >= 500) {
      await new Promise(res => setTimeout(res, 1000));
      return forwardViberAPI(realToken, endpoint, body, retries - 1);
    }
    throw err;
  }
}

app.use("/admin", basicAuth({
  users: { [ADMIN_USERNAME]: ADMIN_PASSWORD },
  challenge: true,
  unauthorizedResponse: { error: "Unauthorized" }
}));

app.get("/healthz", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), timestamp: new Date().toISOString() });
});

["send_message", "get_info", "transfer_owner", "add_member"].forEach(endpoint => {
  app.post(`/viber/${endpoint}`, async (req, res) => {
    const fakeToken = req.headers["x-fake-token"];
    if (!fakeToken) return res.status(401).json({ error: "Missing X-Fake-Token header" });

    const map = loadTokenMap();
    const profile = map[fakeToken];
    if (!profile) return res.status(403).json({ error: "Invalid token" });

    try {
      const response = await forwardViberAPI(profile.real_token, endpoint, req.body);
      logRequest({ type: "viber_api", ip: req.ip, fakeToken, endpoint, status: response.status, response: response.data });
      res.status(response.status).json(response.data);
    } catch (err) {
      const errorData = {
        type: "viber_api_error",
        ip: req.ip,
        fakeToken,
        endpoint,
        error: err.message,
        status: err.response?.status || 500,
        response: err.response?.data
      };
      logRequest(errorData);
      res.status(errorData.status).json({ error: "Viber API Error", detail: err.message, response: err.response?.data });
    }
  });
});

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
  try {
    fs.writeFileSync(fakeBotFile, JSON.stringify(data, null, 2), "utf8");
  } catch (e) {
    console.error("Failed to save fake bots:", e);
  }
}

app.get("/viber/fake_info", (req, res) => {
  const fakeToken = req.headers["x-fake-token"];
  if (!fakeToken) return res.status(400).json({ error: "Missing fake token" });
  const info = loadFakeBots()[fakeToken];
  if (!info) return res.status(404).json({ error: "No fake bot info found" });
  res.json({ status: "ok", info });
});

app.post("/viber/fake_info", (req, res) => {
  const fakeToken = req.headers["x-fake-token"];
  const { name, uri, icon, background } = req.body;
  if (!fakeToken) return res.status(400).json({ error: "Missing fake token" });

  const data = loadFakeBots();
  data[fakeToken] = { name, uri, icon, background, updatedAt: new Date().toISOString() };
  saveFakeBots(data);
  res.json({ status: "ok", message: "Fake bot info updated" });
});

app.get("/admin/api/token-map", (req, res) => {
  res.json(loadTokenMap());
});

app.get("/admin/api/logs", (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
  const searchToken = req.query.token;
  try {
    let logs = fs.readFileSync(path.join(logDir, "requests.log"), "utf8").trim().split("\n").reverse();
    if (searchToken) logs = logs.filter(line => line.includes(`"fakeToken":"${searchToken}"`));
    res.json(logs.slice(0, limit).map(line => {
      try {
        return JSON.parse(line);
      } catch {
        return { error: "Invalid log line" };
      }
    }));
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
    fs.writeFileSync(TOKEN_PATH, JSON.stringify(map, null, 2), "utf8");
    tokenMapCache = null;
    res.json({ status: "ok", message: "Token added" });
  } catch (e) {
    res.status(500).json({ error: "Failed to write token map" });
  }
});

// ✅ Webhook endpoint
app.post("/viber/webhook/:uri", express.raw({ type: "*/*" }), (req, res) => {
  const uri = req.params.uri;
  const signature = req.headers['x-viber-content-signature'];
  const map = loadTokenMap();

  const fakeToken = Object.keys(map).find(token => map[token].uri === uri);
  if (!fakeToken) return res.status(404).json({ error: "Unknown URI" });

  const realToken = map[fakeToken].real_token;
  const computedSignature = crypto.createHmac("sha256", realToken).update(req.body).digest("hex");
  if (signature !== computedSignature) return res.status(403).json({ error: "Invalid signature" });

  const payload = JSON.parse(req.body.toString());
  logRequest({ type: "webhook", uri, fakeToken, ip: req.ip, event: payload.event, data: payload });

  if (payload.event === "webhook") return res.json({ status: 0 });
  res.status(200).json({ status: 0 });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  logRequest({ type: "server_error", error: err.message, stack: process.env.NODE_ENV === "development" ? err.stack : undefined });
  res.status(500).json({ error: "Internal Server Error" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Viber Token Gateway running on port ${PORT}`);
});
