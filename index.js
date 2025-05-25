const express = require("express");
const cors = require("cors");
const basicAuth = require("express-basic-auth");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(cors()); // Allow cross-origin requests
app.use(express.json());
app.use(express.static("public"));

const logFile = path.join(__dirname, "logs", "requests.log");
const tokenMap = require("./tokens.json");
const fakeInfoDir = path.join(__dirname, "fake_info");
if (!fs.existsSync(fakeInfoDir)) fs.mkdirSync(fakeInfoDir);

// ---------------- Admin Auth ----------------
app.use("/admin", basicAuth({
  users: { [process.env.ADMIN_USERNAME]: process.env.ADMIN_PASSWORD },
  challenge: true,
  unauthorizedResponse: () => "Unauthorized",
}));

// ---------------- Admin UI Routes ----------------
app.get("/admin/ui", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/admin/api/token-map", (req, res) => {
  res.json(tokenMap);
});

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

app.get("/admin/api/download-logs", (req, res) => {
  res.download(logFile, "logs.json");
});

// ---------------- Client API: Fake Bot Info ----------------

// GET bot info from token
app.get("/viber/fake_info", (req, res) => {
  const fakeToken = req.header("X-Fake-Token");
  if (!fakeToken) return res.status(400).json({ error: "Missing X-Fake-Token header" });

  const filePath = path.join(fakeInfoDir, `${fakeToken}.json`);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: "No fake bot info found" });
  }

  const data = JSON.parse(fs.readFileSync(filePath, "utf8"));
  res.json({ status: "ok", info: data });
});

// POST or update fake bot info
app.post("/viber/fake_info", (req, res) => {
  const fakeToken = req.header("X-Fake-Token");
  if (!fakeToken) return res.status(400).json({ error: "Missing X-Fake-Token header" });

  const { name, uri, icon, background } = req.body;
  if (!name || !uri) return res.status(400).json({ error: "Missing required fields" });

  const data = {
    name,
    uri,
    icon,
    background,
    updatedAt: new Date().toISOString()
  };

  const filePath = path.join(fakeInfoDir, `${fakeToken}.json`);
  fs.writeFileSync(filePath, JSON.stringify(data));

  // Log update
  const logEntry = {
    time: new Date().toISOString(),
    fakeToken,
    action: "set_fake_info",
    info: data
  };
  fs.appendFileSync(logFile, JSON.stringify(logEntry) + "\n");

  res.json({ status: "ok", message: "Fake bot info updated" });
});

// ---------------- Start Server ----------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Viber Token Gateway running on port ${PORT}`);
});
