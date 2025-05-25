require("dotenv").config();
const express = require("express");
const axios = require("axios");
const app = express();
app.use(express.json());

const tokenMap = {
  "FAKE_TOKEN_555": process.env.TOKEN_FAKE_TOKEN_555,
  "FAKE_TEST_123": process.env.TOKEN_FAKE_TEST_123
};

app.post("/viber/send_message", async (req, res) => {
  const fakeToken = req.headers["x-fake-token"];
  const realToken = tokenMap[fakeToken];

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
    res.status(viberRes.status).json(viberRes.data);
  } catch (err) {
    res.status(500).json({ error: "Viber API Error", detail: err.message });
  }
});

app.listen(3000, () => console.log("Gateway running on port 3000"));
