require("dotenv").config();
const express = require("express");
const axios = require("axios");
const rateLimit = require("express-rate-limit");
const basicAuth = require("express-basic-auth");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json());
app.set("trust proxy", 1);

// Rate limiter
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: "Too many requests, please try again later." },
});
app.use(limiter);

// Log setup
const logDir = path.join(__dirname, "logs");
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir);
const logFile = path.join(logDir, "requests.log");
const fakeBotFile = path.join(__dirname, "fake_bots.json");

// Load token map
const tokenMap = require("./tokens.json");

function logRequest(entry) {
  const logLine = JSON.stringify(entry) + "\n";
  fs.appendFile(logFile, logLine, (err) => {
    if (err) console.error("Failed to write log:", err);
  });
}

function getBotProfile(fakeToken) {
  const map = tokenMap[fakeToken];
  return map ? { ...map, fakeToken } : null;
}

async function forwardViberAPI(realToken, endpoint, body = {}) {
  return await axios.post(
    `https://chatapi.viber.com/pa/${endpoint}`,
    body,
    {
      headers: {
        "X-Viber-Auth-Token": realToken,
        "Content-Type": "application/json",
      },
    }
  );
}

// Root route
app.get("/", (req, res) => {
  res.send("Viber Token Gateway is running. Available endpoints: /viber/send_message, /viber/get_info, /viber/transfer_owner, /viber/invite, /viber/add_member, /viber/fake_info");
});

// Standard Viber endpoints
const viberEndpoints = ["send_message", "get_info", "transfer_owner", "add_member"];
viberEndpoints.forEach((endpoint) => {
  app.post(`/viber/${endpoint}`, async (req, res) => {
    const profile = getBotProfile(req.headers["x-fake-token"]);
    if (!profile) return res.status(403).json({ error: "Invalid token" });

    try {
      const viberRes = await forwardViberAPI(profile.real_token, endpoint, req.body);
      logRequest({
        timestamp: new Date().toISOString(),
        ip: req.ip,
        fakeToken: profile.fakeToken,
        endpoint: `/viber/${endpoint}`,
        body: req.body,
        response: viberRes.data,
      });
      res.status(viberRes.status).json(viberRes.data);
    } catch (err) {
      logRequest({
        timestamp: new Date().toISOString(),
        ip: req.ip,
        fakeToken: profile.fakeToken,
        endpoint: `/viber/${endpoint}`,
        body: req.body,
        error: err.message,
        response: err.response?.data,
      });
      res.status(500).json({
        error: "Viber API Error",
        detail: err.message,
        response: err.response?.data,
      });
    }
  });
});

// Invite link generator
app.post("/viber/invite", (req, res) => {
  const profile = getBotProfile(req.headers["x-fake-token"]);
  if (!profile) return res.status(403).json({ error: "Invalid token" });

  try {
    const uri = profile.fake_uri || profile.uri;
    const inviteLinks = {
      status: 0,
      deep_link: `viber://pa?chatURI=${uri}`,
      web_link: `https://chats.viber.com/${uri}`,
      real_uri: profile.uri,
      message: "For unpublished bots, manually add users using /viber/add_member",
    };
    res.json(inviteLinks);
  } catch (err) {
    res.status(500).json({ error: "Failed to generate invite link", detail: err.message });
  }
});

// Fake bot info GET
app.get("/viber/fake_info", (req, res) => {
  const fakeToken = req.headers["x-fake-token"];
  if (!fakeToken) return res.status(400).json({ error: "Missing fake token" });

  try {
    const data = JSON.parse(fs.readFileSync(fakeBotFile, "utf8"));
    const info = data[fakeToken];
    if (!info) return res.status(404).json({ error: "No fake bot info found" });

    res.json({ status: "ok", info });
  } catch (e) {
    res.status(500).json({ error: "Failed to read fake bot info" });
  }
});

// Fake bot info UPDATE
app.post("/viber/fake_info", (req, res) => {
  const fakeToken = req.headers["x-fake-token"];
  const { name, uri, icon, background } = req.body;
  if (!fakeToken) return res.status(400).json({ error: "Missing fake token" });

  try {
    const data = fs.existsSync(fakeBotFile)
      ? JSON.parse(fs.readFileSync(fakeBotFile, "utf8"))
      : {};

    data[fakeToken] = { name, uri, icon, background };
    fs.writeFileSync(fakeBotFile, JSON.stringify(data, null, 2), "utf8");

    res.json({ status: "ok", message: "Fake bot info updated" });
  } catch (e) {
    res.status(500).json({ error: "Failed to update fake bot info" });
  }
});

// Admin Auth
app.use("/admin", basicAuth({
  users: { [process.env.ADMIN_USERNAME]: process.env.ADMIN_PASSWORD },
  challenge: true,
  unauthorizedResponse: () => "Unauthorized",
}));

// Admin Dashboard
app.get("/admin", (req, res) => {
  fs.readFile(logFile, "utf8", (err, data) => {
    if (err) return res.status(500).send("Failed to load logs");

    const logs = data.trim().split("\n").map(line => JSON.parse(line)).reverse().slice(0, 50);
    res.send(`
      <h1>Admin Dashboard</h1>
      <h2>Token Map (tokens.json)</h2>
      <pre>${JSON.stringify(tokenMap, null, 2)}</pre>
      <h2>Recent Request Logs (latest 50)</h2>
      <pre>${JSON.stringify(logs, null, 2)}</pre>
    `);
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Gateway running on port ${PORT}`));
