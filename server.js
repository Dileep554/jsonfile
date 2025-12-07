const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const https = require("https");
const { HttpsProxyAgent } = require("https-proxy-agent");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

/* ================= PROXY CONFIG (HARDCODED) ================= */

const PROXY_URL = "http://proxy.conexus.svc.local:3128";

/* If you want env override, uncomment below
const PROXY_URL =
  process.env.https_proxy ||
  process.env.http_proxy ||
  "http://proxy.conexus.svc.local:3128";
*/

const proxyAgent = new HttpsProxyAgent(PROXY_URL);

/* ============================================================= */

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

/* ---------- SSL EXPIRY (VIA PROXY) ---------- */
function getSSLCertExpiry(url) {
  return new Promise((resolve, reject) => {
    try {
      const parsed = new URL(url);

      const options = {
        hostname: parsed.hostname,
        port: 443,
        method: "GET",
        path: "/",                 // ✅ path NOT required for cert
        agent: proxyAgent,         // ✅ proxy tunnel
        rejectUnauthorized: false  // ✅ internal certs
      };

      const req = https.request(options, res => {
        const cert = res.socket.getPeerCertificate(true);

        if (!cert || !cert.valid_to) {
          return reject("Certificate not found");
        }

        resolve(cert.valid_to);
      });

      req.on("error", err => reject(err.message));
      req.end();
    } catch (err) {
      reject(err.message);
    }
  });
}

/* ---------- CHECK SSL ---------- */
app.post("/check-ssl", async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || !url.startsWith("https://")) {
      return res.json({ expiryDate: "Invalid URL", daysLeft: "-" });
    }

    const expiryDate = await getSSLCertExpiry(url);

    const daysLeft = Math.ceil(
      (new Date(expiryDate) - new Date()) / (1000 * 60 * 60 * 24)
    );

    res.json({
      expiryDate: new Date(expiryDate).toISOString().split("T")[0],
      daysLeft
    });
  } catch (err) {
    res.json({
      expiryDate: "Unable to read (Proxy/VPN)",
      daysLeft: "-"
    });
  }
});

/* ---------- APPS API ---------- */
app.get("/apps", (req, res) => {
  res.json(readApps());
});

app.post("/apps", (req, res) => {
  const { app: a, env, url, adminPassword } = req.body;

  if (adminPassword !== ADMIN_PASSWORD) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const apps = readApps();
  apps.push({ app: a, env, url });
  writeApps(apps);
  res.json(apps);
});

app.delete("/apps", (req, res) => {
  const { url, adminPassword } = req.body;

  if (adminPassword !== ADMIN_PASSWORD) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const apps = readApps().filter(a => a.url !== url);
  writeApps(apps);
  res.json(apps);
});

/* ---------- START ---------- */
app.listen(3000, () => {
  console.log("✅ Server running at http://localhost:3000");
  console.log("✅ Proxy in use:", PROXY_URL);
});
