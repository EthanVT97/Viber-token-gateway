require("dotenv").config();
const express = require("express");
const axios = require("axios");
const rateLimit = require("express-rate-limit");
const basicAuth = require("express-basic-auth");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json());

// IMPORTANT: Reverse proxy အောက်မှာ IP ကိုတိတိကျကျ ဖော်ထုတ်ဖို့
app.set("trust proxy", 1);

// Root route for health check / test
app.get("/", (req, res) => {
  res.send("Viber Token Gateway is running. Use /viber/send_message API.");
});

// Token map from environment variables
const tokenMap = {
  "FAKE_TOKEN_555": process.env.TOKEN_FAKE_TOKEN_555,
  "FAKE_TEST_123": process.env.TOKEN_FAKE_TEST_123,
};

// Rate limiter setup (30 requests per minute per IP)
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  message: { error: "Too many requests, please try again later." },
});
app.use(limiter);

// Setup log directory and file
const logDir = path.join(__dirname, "logs");
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir);
const logFile = path.join(logDir, "requests.log");

// Function to append log entries to file
function logRequest(entry) {
  const logLine = JSON.stringify(entry) + "\n";
  fs.appendFile(logFile, logLine, (err) => {
    if (err) console.error("Failed to write log:", err);
  });
}

// Main proxy API endpoint
app.post("/viber/send_message", async (req, res) => {
  const fakeToken = req.headers["x-fake-token"];
  const realToken = tokenMap[fakeToken];

  if (!realToken) return res.status(403).json({ error: "Invalid token" });

  // Log request info
  logRequest({
    timestamp: new Date().toISOString(),
    ip: req.ip,
    fakeToken,
    endpoint: "/viber/send_message",
    body: req.body,
  });

  try {
    // Forward request to Viber API with real token
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
    res.status(viberRes.status).json(viberRes.data);
  } catch (err) {
    res.status(500).json({ error: "Viber API Error", detail: err.message });
  }
});

// Admin dashboard with basic auth protection
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Gateway running on port ${PORT}`));
