const express = require("express");
const cors = require("cors");
const tls = require("tls");

const app = express();
app.use(cors());
app.use(express.json());

const ADMIN_PASSWORD = "Dwsazureadmin@";
let apps = [];

app.get("/apps", (req, res) => res.json(apps));

app.post("/apps", (req, res) => {
  if (req.body.adminPassword !== ADMIN_PASSWORD)
    return res.status(403).end();

  apps.push(req.body);
  res.json({ success: true });
});

app.delete("/apps", (req, res) => {
  if (req.body.adminPassword !== ADMIN_PASSWORD)
    return res.status(403).end();

  apps = apps.filter(a => a.url !== req.body.url);
  res.json({ success: true });
});

app.put("/update-expiry", (req, res) => {
  if (req.body.adminPassword !== ADMIN_PASSWORD)
    return res.status(403).end();

  const appItem = apps.find(a => a.url === req.body.url);
  if (!appItem) return res.status(404).end();

  appItem.expiryDate = req.body.expiryDate;
  res.json({ success: true });
});

app.post("/check-ssl", (req, res) => {
  try {
    const host = new URL(req.body.url).hostname;

    const socket = tls.connect(443, host, { servername: host }, () => {
      const cert = socket.getPeerCertificate();
      const expiry = new Date(cert.valid_to);
      const daysLeft = Math.ceil((expiry - new Date()) / 86400000);

      res.json({
        expiryDate: expiry.toISOString().split("T")[0],
        daysLeft
      });

      socket.end();
    });

    socket.on("error", () =>
      res.json({ expiryDate: "N/A", daysLeft: Infinity })
    );
  } catch {
    res.json({ expiryDate: "N/A", daysLeft: Infinity });
  }
});

app.listen(3000, () => console.log("✅ Server running on 3000"));
