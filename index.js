const express = require("express");
const basicAuth = require("express-basic-auth");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.static("public"));

const tokenMap = require("./tokens.json");
const logFile = path.join(__dirname, "logs", "requests.log");

// Admin auth
app.use("/admin", basicAuth({
  users: { [process.env.ADMIN_USERNAME]: process.env.ADMIN_PASSWORD },
  challenge: true,
  unauthorizedResponse: () => "Unauthorized",
}));

// Serve admin UI
app.get("/admin/ui", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// API: Get token map
app.get("/admin/api/token-map", (req, res) => {
  res.json(tokenMap);
});

// API: Get latest logs
app.get("/admin/api/logs", (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  fs.readFile(logFile, "utf8", (err, data) => {
    if (err) return res.status(500).json({ error: "Failed to read logs" });
    const logs = data
      .trim()
      .split("\n")
      .map(line => JSON.parse(line))
      .reverse()
      .slice(0, limit);
    res.json(logs);
  });
});

// API: Search logs by fake token
app.get("/admin/api/search-logs", (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: "Missing token" });

  fs.readFile(logFile, "utf8", (err, data) => {
    if (err) return res.status(500).json({ error: "Failed to read logs" });
    const filtered = data
      .trim()
      .split("\n")
      .map(line => JSON.parse(line))
      .filter(entry => entry.fakeToken === token)
      .reverse();
    res.json(filtered);
  });
});

// API: Download logs
app.get("/admin/api/download-logs", (req, res) => {
  res.download(logFile, "logs.json");
});
