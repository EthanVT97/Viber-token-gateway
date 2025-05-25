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

// Root route
app.get("/", (req, res) => {
  res.send("Viber Token Gateway is running. Available endpoints: /viber/send_message, /viber/get_info, /viber/transfer_owner, /viber/invite, /viber/add_member");
});

// Token map
const tokenMap = {
  "FAKE_TOKEN_555": process.env.TOKEN_FAKE_TOKEN_555,
  "FAKE_TEST_123": process.env.TOKEN_FAKE_TEST_123,
};

// Rate limiter
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: "Too many requests, please try again later." },
});
app.use(limiter);

// Logs
const logDir = path.join(__dirname, "logs");
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir);
const logFile = path.join(logDir, "requests.log");

function logRequest(entry) {
  const logLine = JSON.stringify(entry) + "\n";
  fs.appendFile(logFile, logLine, (err) => {
    if (err) console.error("Failed to write log:", err);
  });
}

// Utility: Get real token from fake token
function getRealToken(req) {
  const fakeToken = req.headers["x-fake-token"];
  const realToken = tokenMap[fakeToken];
  return { fakeToken, realToken };
}

// ==================== VIBER API ENDPOINTS ====================

app.post("/viber/send_message", async (req, res) => {
  const { fakeToken, realToken } = getRealToken(req);
  if (!realToken) return res.status(403).json({ error: "Invalid token" });

  try {
    const viberRes = await axios.post(
      "https://chatapi.viber.com/pa/send_message",
      req.body,
      {
        headers: {
          "X-Viber-Auth-Token": realToken,
          "Content-Type": "application/json",
        },
      }
    );
    logRequest({
      timestamp: new Date().toISOString(),
      ip: req.ip,
      fakeToken,
      endpoint: "/viber/send_message",
      body: req.body,
      response: viberRes.data,
    });
    res.status(viberRes.status).json(viberRes.data);
  } catch (err) {
    logRequest({
      timestamp: new Date().toISOString(),
      ip: req.ip,
      fakeToken,
      endpoint: "/viber/send_message",
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

app.post("/viber/get_info", async (req, res) => {
  const { fakeToken, realToken } = getRealToken(req);
  if (!realToken) return res.status(403).json({ error: "Invalid token" });

  try {
    const viberRes = await axios.post(
      "https://chatapi.viber.com/pa/get_account_info",
      {},
      {
        headers: {
          "X-Viber-Auth-Token": realToken,
          "Content-Type": "application/json",
        },
      }
    );
    logRequest({
      timestamp: new Date().toISOString(),
      ip: req.ip,
      fakeToken,
      endpoint: "/viber/get_info",
      response: viberRes.data,
    });
    res.status(viberRes.status).json(viberRes.data);
  } catch (err) {
    logRequest({
      timestamp: new Date().toISOString(),
      ip: req.ip,
      fakeToken,
      endpoint: "/viber/get_info",
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

app.post("/viber/transfer_owner", async (req, res) => {
  const { fakeToken, realToken } = getRealToken(req);
  if (!realToken) return res.status(403).json({ error: "Invalid token" });

  const { from, to } = req.body;
  if (!from || !to) return res.status(400).json({ error: "Both 'from' and 'to' user IDs are required" });

  try {
    const viberRes = await axios.post(
      "https://chatapi.viber.com/pa/transfer_account",
      { from, to },
      {
        headers: {
          "X-Viber-Auth-Token": realToken,
          "Content-Type": "application/json",
        },
      }
    );
    logRequest({
      timestamp: new Date().toISOString(),
      ip: req.ip,
      fakeToken,
      endpoint: "/viber/transfer_owner",
      body: req.body,
      response: viberRes.data,
    });
    res.status(viberRes.status).json(viberRes.data);
  } catch (err) {
    logRequest({
      timestamp: new Date().toISOString(),
      ip: req.ip,
      fakeToken,
      endpoint: "/viber/transfer_owner",
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

app.post("/viber/invite", async (req, res) => {
  const { fakeToken, realToken } = getRealToken(req);
  if (!realToken) return res.status(403).json({ error: "Invalid token" });

  try {
    const viberRes = await axios.post(
      "https://chatapi.viber.com/pa/get_account_info",
      {},
      {
        headers: {
          "X-Viber-Auth-Token": realToken,
          "Content-Type": "application/json",
        },
      }
    );

    const botUri = viberRes.data.uri;
    if (!botUri) throw new Error("Bot URI not found");

    const inviteLinks = {
      status: 0,
      deep_link: `viber://pa?chatURI=${botUri}`,
      web_link: `https://chats.viber.com/${botUri}`,
      message: "For unpublished bots, admin must manually add members using /viber/add_member",
    };

    logRequest({
      timestamp: new Date().toISOString(),
      ip: req.ip,
      fakeToken,
      endpoint: "/viber/invite",
      response: inviteLinks,
    });

    res.json(inviteLinks);
  } catch (err) {
    logRequest({
      timestamp: new Date().toISOString(),
      ip: req.ip,
      fakeToken,
      endpoint: "/viber/invite",
      error: err.message,
      response: err.response?.data,
    });

    res.status(500).json({
      error: "Failed to generate invite link",
      detail: err.message,
      response: err.response?.data,
    });
  }
});

app.post("/viber/add_member", async (req, res) => {
  const { fakeToken, realToken } = getRealToken(req);
  if (!realToken) return res.status(403).json({ error: "Invalid token" });

  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: "user_id is required" });

  try {
    const viberRes = await axios.post(
      "https://chatapi.viber.com/pa/add_member",
      { id: user_id },
      {
        headers: {
          "X-Viber-Auth-Token": realToken,
          "Content-Type": "application/json",
        },
      }
    );

    logRequest({
      timestamp: new Date().toISOString(),
      ip: req.ip,
      fakeToken,
      endpoint: "/viber/add_member",
      body: req.body,
      response: viberRes.data,
    });

    res.status(viberRes.status).json(viberRes.data);
  } catch (err) {
    logRequest({
      timestamp: new Date().toISOString(),
      ip: req.ip,
      fakeToken,
      endpoint: "/viber/add_member",
      body: req.body,
      error: err.message,
      response: err.response?.data,
    });

    res.status(500).json({
      error: "Failed to add member",
      detail: err.message,
      response: err.response?.data,
      note: "Ensure the bot is public or you're an admin adding members manually",
    });
  }
});

// ==================== ADMIN DASHBOARD ====================

app.use(
  "/admin",
  basicAuth({
    users: { [process.env.ADMIN_USERNAME]: process.env.ADMIN_PASSWORD },
    challenge: true,
    unauthorizedResponse: () => "Unauthorized",
  })
);

app.get("/admin", (req, res) => {
  fs.readFile(logFile, "utf8", (err, data) => {
    if (err) {
      return res.status(500).send("Failed to load logs");
    }
    const logs = data
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line))
      .reverse()
      .slice(0, 50);

    res.send(`
      <h1>Admin Dashboard</h1>
      <h2>Token Map</h2>
      <pre>${JSON.stringify(tokenMap, null, 2)}</pre>
      <h2>Recent Request Logs (latest 50)</h2>
      <pre>${JSON.stringify(logs, null, 2)}</pre>
    `);
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Gateway running on port ${PORT}`));
