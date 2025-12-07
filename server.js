const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const tls = require("tls");
 
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));
 
const DATA_FILE = path.join(__dirname, "apps.json");
const ADMIN_PASSWORD = "Dwsazureadmin@";
 
/* ---------- helpers ---------- */
function readApps() {
  if (!fs.existsSync(DATA_FILE)) return [];
  return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
}
 
function writeApps(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}
 
/* ---------- SSL expiry ---------- */
function getSSLCertExpiry(hostname, port = 443) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,          // ✅ REQUIRED for SNI
        rejectUnauthorized: false
      },
      () => {
        const cert = socket.getPeerCertificate();
        socket.end();
 
        if (!cert || !cert.valid_to) {
          return reject("Certificate not found");
        }
 
        resolve(cert.valid_to);
      }
    );
 
    socket.on("error", err => reject(err.message));
  });
}
 
/* ---------- CHECK SSL ---------- */
app.post("/check-ssl", async (req, res) => {
  try {
    const { url } = req.body;
 
    if (!url || !url.startsWith("https://")) {
      return res.json({ expiryDate: "N/A", daysLeft: Infinity });
    }
 
    // ✅ THIS FIXES EVERYTHING
    const parsed = new URL(url);
    const hostname = parsed.hostname;   // ✅ removes path safely
    const port = parsed.port || 443;
 
    const expiryDate = await getSSLCertExpiry(hostname, port);
 
    const daysLeft = Math.ceil(
      (new Date(expiryDate) - new Date()) / (1000 * 60 * 60 * 24)
    );
 
    res.json({ expiryDate, daysLeft });
  } catch (e) {
    res.json({ expiryDate: "N/A", daysLeft: Infinity });
  }
});
 
/* ---------- Apps API ---------- */
app.get("/apps", (req, res) => {
  res.json(readApps());
});
 
app.post("/apps", (req, res) => {
  const { app: a, env, url, adminPassword } = req.body;
 
  if (adminPassword !== ADMIN_PASSWORD)
    return res.status(401).json({ message: "Unauthorized" });
 
  const apps = readApps();
  apps.push({ app: a, env, url });
  writeApps(apps);
  res.json(apps);
});
 
app.delete("/apps", (req, res) => {
  const { url, adminPassword } = req.body;
 
  if (adminPassword !== ADMIN_PASSWORD)
    return res.status(401).json({ message: "Unauthorized" });
 
  const apps = readApps().filter(a => a.url !== url);
  writeApps(apps);
  res.json(apps);
});
 
/* ---------- START ---------- */
app.listen(3000, () =>
  console.log("✅ Server running at http://localhost:3000")
);
 
