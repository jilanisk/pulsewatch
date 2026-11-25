"use strict";

require("dotenv").config();

// console.log("SMTP USER:", process.env.SMTP_USER);
// console.log("SMTP PASSWORD LOADED:", !!process.env.SMTP_PASS);
// console.log("SMTP PASSWORD LENGTH:", process.env.SMTP_PASS?.length);
// const password = process.env.SMTP_PASS;

// console.log("SMTP password loaded:", !!password);
// console.log("Password length:", password?.length);
// console.log("Password contains @:", password?.includes("@"));
// console.log("Password contains #:", password?.includes("#"));
// console.log("Password contains !:", password?.includes("!"));

const express = require("express");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const dns = require("node:dns").promises;
const net = require("node:net");
const http = require("node:http");
const https = require("node:https");
const ipaddr = require("ipaddr.js");
const { DatabaseSync } = require("node:sqlite");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const INTERVAL = Math.max(15000, Number(process.env.CHECK_INTERVAL || 60000));
const CONCURRENCY = Math.min(50, Math.max(1, Number(process.env.CHECK_CONCURRENCY || 10)));
const TIMEOUT = Math.min(30000, Math.max(1000, Number(process.env.CHECK_TIMEOUT || 10000)));
const DATA_DIR = path.resolve(process.env.DATA_DIR || "./data");
const DB_FILE = path.join(DATA_DIR, "pulsewatch.sqlite");
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const COOKIE_SECURE =
    process.env.COOKIE_SECURE === "true" ||
    (process.env.COOKIE_SECURE !== "false" && process.env.NODE_ENV === "production");
fs.mkdirSync(DATA_DIR, { recursive: true });
if (
    process.env.NODE_ENV === "production" &&
    (!SESSION_SECRET || SESSION_SECRET.length < 32 || !ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12)
) {
    throw new Error("Production requires SESSION_SECRET (32+ chars) and ADMIN_PASSWORD (12+ chars). Set them in .env.");
}

const db = new DatabaseSync(DB_FILE);
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS sites (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1,
 status TEXT NOT NULL DEFAULT 'pending', response_time INTEGER, status_code INTEGER, last_checked TEXT,
 error TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checks (
 id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
 checked_at TEXT NOT NULL, status TEXT NOT NULL, response_time INTEGER, status_code INTEGER, error TEXT
);
CREATE INDEX IF NOT EXISTS idx_checks_site_time ON checks(site_id, checked_at DESC);
CREATE TABLE IF NOT EXISTS incidents (
 id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
 started_at TEXT NOT NULL, resolved_at TEXT, cause TEXT
);`);

// One-time, idempotent import of V1's sites.json.
const legacyFile = path.join(DATA_DIR, "sites.json");
if (fs.existsSync(legacyFile)) {
    try {
        const legacy = JSON.parse(fs.readFileSync(legacyFile, "utf8"));
        const insertSite = db.prepare(
            `INSERT OR IGNORE INTO sites(id,name,url,status,response_time,status_code,last_checked,error,created_at) VALUES(?,?,?,?,?,?,?,?,?)`
        );
        const insertCheck = db.prepare(
            `INSERT INTO checks(site_id,checked_at,status,response_time,status_code,error) VALUES(?,?,?,?,?,?)`
        );
        const insertIncident = db.prepare(
            `INSERT INTO incidents(site_id,started_at,resolved_at,cause) VALUES(?,?,?,?)`
        );
        for (const s of legacy) {
            if (!s.id || !s.name || !s.url) continue;
            insertSite.run(
                s.id,
                s.name,
                s.url,
                s.status || "pending",
                s.responseTime ?? null,
                s.statusCode ?? null,
                s.lastChecked ?? null,
                s.error ?? null,
                s.createdAt || new Date().toISOString()
            );
            for (const h of (s.history || []).slice(-5000))
                insertCheck.run(s.id, h.time, h.status, h.responseTime ?? null, null, null);
            for (const i of (s.incidents || []).slice(-500))
                insertIncident.run(s.id, i.time, i.status === "up" ? i.time : null, i.message || null);
        }
        fs.renameSync(legacyFile, legacyFile + ".migrated");
        console.log("Imported V1 sites.json into SQLite.");
    } catch (e) {
        console.error("V1 import skipped:", e.message);
    }
}

app.disable("x-powered-by");
app.use(express.json({ limit: "20kb" }));
app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    next();
});
const rateBuckets = new Map();
function rateLimit(max, windowMs) {
    return (req, res, next) => {
        const key = req.ip + ":" + req.path;
        const now = Date.now();
        let b = rateBuckets.get(key);
        if (!b || now > b.until) b = { count: 0, until: now + windowMs };
        b.count++;
        rateBuckets.set(key, b);
        if (b.count > max) return res.status(429).json({ error: "Too many requests. Try again later." });
        next();
    };
}
function sign(value) {
    return crypto
        .createHmac("sha256", SESSION_SECRET || "development-only-secret")
        .update(value)
        .digest("base64url");
}
function setSession(res) {
    const payload = Buffer.from(JSON.stringify({ u: ADMIN_USER, exp: Date.now() + 8 * 60 * 60 * 1000 })).toString(
        "base64url"
    );
    const token = payload + "." + sign(payload);
    res.cookie("pw_session", token, {
        httpOnly: true,
        sameSite: "strict",
        secure: COOKIE_SECURE,
        maxAge: 8 * 60 * 60 * 1000,
        path: "/",
    });
}
function parseCookies(header = "") {
    return Object.fromEntries(
        header
            .split(";")
            .map((v) => v.trim().split(/=(.*)/s).slice(0, 2))
            .filter((x) => x.length === 2)
    );
}
function auth(req, res, next) {
    const token = parseCookies(req.headers.cookie).pw_session;
    if (!token) return res.status(401).json({ error: "Authentication required." });
    const [p, s] = token.split(".");
    if (
        !p ||
        !s ||
        Buffer.byteLength(s) !== Buffer.byteLength(sign(p)) ||
        !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(sign(p)))
    )
        return res.status(401).json({ error: "Session expired. Please sign in." });
    try {
        const data = JSON.parse(Buffer.from(p, "base64url").toString());
        if (data.u !== ADMIN_USER || data.exp < Date.now()) throw Error();
        req.user = data.u;
        next();
    } catch {
        res.clearCookie("pw_session", { path: "/" });
        return res.status(401).json({ error: "Session expired. Please sign in." });
    }
}
app.post("/api/auth/login", rateLimit(8, 60000), (req, res) => {
    const user = String(req.body.username || "");
    const pass = String(req.body.password || "");
    const a = Buffer.from(user),
        b = Buffer.from(ADMIN_USER);
    const userOK = a.length === b.length && crypto.timingSafeEqual(a, b); // Password comparison uses a fixed-time digest comparison.
    const pa = crypto.createHash("sha256").update(pass).digest(),
        pb = crypto.createHash("sha256").update(ADMIN_PASSWORD).digest();
    const passOK = crypto.timingSafeEqual(pa, pb);
    if (!userOK || !passOK) return res.status(401).json({ error: "Invalid username or password." });
    setSession(res);
    res.json({ authenticated: true, user: ADMIN_USER });
});
app.post("/api/auth/logout", (req, res) => {
    res.clearCookie("pw_session", { path: "/" });
    res.json({ success: true });
});
app.get("/api/auth/session", (req, res) => {
    const token = parseCookies(req.headers.cookie).pw_session;
    if (!token) return res.json({ authenticated: false });
    const [p, s] = token.split(".");
    try {
        if (s !== sign(p)) throw Error();
        const d = JSON.parse(Buffer.from(p, "base64url").toString());
        res.json({
            authenticated: d.exp > Date.now() && d.u === ADMIN_USER,
            user: ADMIN_USER,
        });
    } catch {
        res.json({ authenticated: false });
    }
});

function isPublicIP(ip) {
    try {
        return ipaddr.parse(ip).range() === "unicast";
    } catch {
        return false;
    }
}
async function resolvePublic(url) {
    const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal"))
        throw Error("Local and internal hosts are not allowed.");
    const records = net.isIP(host)
        ? [{ address: host, family: net.isIP(host) }]
        : await dns.lookup(host, { all: true, verbatim: true });
    if (!records.length || records.some((r) => !isPublicIP(r.address)))
        throw Error("Private or non-public IP addresses are not allowed.");
    return records[0];
}
async function parseAndValidate(value) {
    let u;
    try {
        u = new URL(value);
    } catch {
        throw Error("Enter a valid URL.");
    }
    if (!["http:", "https:"].includes(u.protocol)) throw Error("Only HTTP and HTTPS are supported.");
    if (u.username || u.password) throw Error("URLs containing credentials are not allowed.");
    if (u.port && !["80", "443"].includes(u.port))
        throw Error("Only standard HTTP/HTTPS ports (80 and 443) are allowed.");
    await resolvePublic(u);
    return u;
}
function requestPinned(url, record, redirects = 0) {
    return new Promise((resolve, reject) => {
        const lib = url.protocol === "https:" ? https : http;
        const req = lib.request(
            url,
            {
                method: "GET",
                headers: { "User-Agent": "PulseWatch/2.0", Accept: "*/*" },
                timeout: TIMEOUT,
                maxHeaderSize: 16 * 1024,
                // lookup: (hostname, opts, cb) => {
                //   if (typeof opts === "function") cb = opts;
                //   cb(null, record.address, record.family);
                // }
                lookup: (hostname, options, callback) => {
                    if (typeof options === "function") {
                        callback = options;
                        options = {};
                    }
                    // Node.js expects an array when all=true
                    if (options && options.all) {
                        return callback(null, [
                            {
                                address: record.address,
                                family: record.family,
                            },
                        ]);
                    }
                    // Normal DNS lookup response
                    return callback(null, record.address, record.family);
                },
            },
            (res) => {
                res.resume();
                resolve({ statusCode: res.statusCode, headers: res.headers });
            }
        );
        req.on("timeout", () => req.destroy(new Error("Request timed out.")));
        req.on("error", reject);
        req.end();
    });
}
// async function performCheck(site) {
 
//     const started = Date.now(),
//         checkedAt = new Date().toISOString();
//     let status = "down",
//         code = null,
//         error = null,
//         record;
//     try {
//         let url = await parseAndValidate(site.url);
//         for (let hop = 0; hop <= 3; hop++) {
//             record = await resolvePublic(url);
//             const result = await requestPinned(url, record);
//             code = result.statusCode;
//             if (code >= 300 && code < 400 && result.headers.location) {
//                 if (hop === 3) throw Error("Too many redirects.");
//                 url = new URL(result.headers.location, url);
//                 if (
//                     !["http:", "https:"].includes(url.protocol) ||
//                     url.username ||
//                     url.password ||
//                     (url.port && !["80", "443"].includes(url.port))
//                 )
//                     throw Error("Unsupported redirect destination.");
//                 continue;
//             }
//             // HTTP 2xx, 3xx and 4xx mean the web server responded.
//             status = code >= 200 && code < 500 ? "up" : "down";

//             if (status === "down") {
//                 error = `HTTP ${code}`;
//             }
//             break;
//         }
//         console.log("MONITOR STATUS:", { name: site.name, previous: prev, current: status, error});
//     } catch (e) {
//         error = String(e.message || "Check failed").slice(0, 500);
//     }
//     const elapsed = Date.now() - started;
//     db.prepare("UPDATE sites SET status=?,response_time=?,status_code=?,last_checked=?,error=? WHERE id=?").run(
//         status,
//         elapsed,
//         code,
//         checkedAt,
//         error,
//         site.id
//     );
//     db.prepare("INSERT INTO checks(site_id,checked_at,status,response_time,status_code,error) VALUES(?,?,?,?,?,?)").run(
//         site.id,
//         checkedAt,
//         status,
//         elapsed,
//         code,
//         error
//     );
//     const currentSite = db.prepare("SELECT status FROM sites WHERE id=?").get(site.id);

//     const prev = currentSite?.status ?? site.status;

//     if (status === "down" && prev !== "down") {
//         db.prepare("INSERT INTO incidents(site_id,started_at,cause) VALUES(?,?,?)").run(site.id, checkedAt, error);
//       await notify(site.name, site.url, "down", error);
//     }
    
//     if (status === "up" && prev === "down") {
//         db.prepare("UPDATE incidents SET resolved_at=? WHERE site_id=? AND resolved_at IS NULL").run(
//             checkedAt,
//             site.id
//         );
//         await notify(site.name, site.url, "up", "Website recovered");
//     }
//     console.log("WEBSITE STATUS TRANSITION:", { website: site.name, previousStatus: prev, currentStatus: status });
//     // Keep bounded history (90 days at 1-minute interval).
//     db.prepare(
//         "DELETE FROM checks WHERE site_id=? AND id NOT IN (SELECT id FROM checks WHERE site_id=? ORDER BY checked_at DESC LIMIT 129600)"
//     ).run(site.id, site.id);
//     return {
//         status,
//         responseTime: elapsed,
//         statusCode: code,
//         lastChecked: checkedAt,
//         error,
//     };
// }
async function performCheck(site) {

    const started = Date.now();
    const checkedAt = new Date().toISOString();

    // IMPORTANT: Capture previous status BEFORE updating the database.
    const previousStatus = site.status;

    let status = "down";
    let code = null;
    let error = null;
    let record;

    try {
        let url = await parseAndValidate(site.url);

        for (let hop = 0; hop <= 3; hop++) {

            record = await resolvePublic(url);

            const result = await requestPinned(url, record);

            code = result.statusCode;

            if (code >= 300 && code < 400 && result.headers.location) {

                if (hop === 3) {
                    throw Error("Too many redirects.");
                }

                url = new URL(result.headers.location, url);

                if (
                    !["http:", "https:"].includes(url.protocol) ||
                    url.username ||
                    url.password ||
                    (url.port && !["80", "443"].includes(url.port))
                ) {
                    throw Error("Unsupported redirect destination.");
                }

                continue;
            }

            // HTTP 2xx, 3xx and 4xx mean server responded.
            status = code >= 200 && code < 500 ? "up" : "down";

            if (status === "down") {
                error = `HTTP ${code}`;
            }

            break;
        }

    } catch (e) {
        error = String(e.message || "Check failed").slice(0, 500);
    }

    const elapsed = Date.now() - started;

    // Log the actual transition.
    console.log("WEBSITE STATUS TRANSITION:", {
        website: site.name,
        previousStatus,
        currentStatus: status,
        statusCode: code,
        error
    });

    // Save latest monitoring status.
    db.prepare(`
        UPDATE sites
        SET status=?,
            response_time=?,
            status_code=?,
            last_checked=?,
            error=?
        WHERE id=?
    `).run(
        status,
        elapsed,
        code,
        checkedAt,
        error,
        site.id
    );

    // Save monitoring history.
    db.prepare(`
        INSERT INTO checks(
            site_id,
            checked_at,
            status,
            response_time,
            status_code,
            error
        )
        VALUES(?,?,?,?,?,?)
    `).run(
        site.id,
        checkedAt,
        status,
        elapsed,
        code,
        error
    );

    // Detect actual status transitions.
    if (status === "down" && previousStatus !== "down") {

        db.prepare(`
            INSERT INTO incidents(site_id, started_at, cause)
            VALUES(?,?,?)
        `).run(site.id, checkedAt, error);

        console.log("DOWNTIME ALERT TRIGGERED:", site.name);

        await notify(
            site.name,
            site.url,
            "down",
            error
        );
    }

    if (status === "up" && previousStatus === "down") {

        db.prepare(`
            UPDATE incidents
            SET resolved_at=?
            WHERE site_id=? AND resolved_at IS NULL
        `).run(checkedAt, site.id);

        console.log("RECOVERY ALERT TRIGGERED:", site.name);

        await notify(
            site.name,
            site.url,
            "up",
            "Website recovered"
        );
    }

    // Keep bounded history (90 days at 1-minute interval).
    db.prepare(`
        DELETE FROM checks
        WHERE site_id=?
        AND id NOT IN (
            SELECT id
            FROM checks
            WHERE site_id=?
            ORDER BY checked_at DESC
            LIMIT 129600
        )
    `).run(site.id, site.id);

    return {
        status,
        responseTime: elapsed,
        statusCode: code,
        lastChecked: checkedAt,
        error
    };
}
let checking = false;



async function notify(name, url, state, detail) {
    const recipient = process.env.ALERT_EMAIL_TO;

    if (!process.env.SMTP_HOST || !recipient) {
        console.error("EMAIL ALERT SKIPPED:", {
            smtpConfigured: !!process.env.SMTP_HOST,
            recipientConfigured: !!recipient
        });
        return;
    }

    try {
        const nodemailer = require("nodemailer");

        const transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: Number(process.env.SMTP_PORT || 465),
            secure: process.env.SMTP_SECURE === "true",
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS
            }
        });

        const subject = `[PulseWatch] ${name} ${state.toUpperCase()}`;

        const info = await transporter.sendMail({
            from: process.env.ALERT_EMAIL_FROM || process.env.SMTP_USER,
            to: recipient,
            subject,
            text: `
Website: ${name}
URL: ${url}
Status: ${state.toUpperCase()}
Details: ${detail || "No additional details"}
Time: ${new Date().toISOString()}
            `
        });

        console.log("ALERT EMAIL SENT:", {
            website: name,
            state,
            recipient,
            accepted: info.accepted,
            rejected: info.rejected,
            messageId: info.messageId
        });

    } catch (error) {
        console.error("ALERT EMAIL FAILED:", {
            website: name,
            state,
            error: error.message
        });
    }
}

async function runChecks() {
    if (checking) return;
    checking = true;
    try {
        const rows = db.prepare("SELECT * FROM sites WHERE enabled=1").all();
        let cursor = 0;
        const workers = Array.from({ length: Math.min(CONCURRENCY, rows.length) }, async () => {
            while (cursor < rows.length) {
                const site = rows[cursor++];
                await performCheck(site);
            }
        });
        await Promise.all(workers);
    } finally {
        checking = false;
    }
}

function getSites() {
    const rows = db.prepare("SELECT * FROM sites ORDER BY created_at DESC").all();
    return rows.map((s) => {
        const history = db
            .prepare(
                "SELECT checked_at AS time,status,response_time AS responseTime,status_code AS statusCode FROM checks WHERE site_id=? ORDER BY checked_at DESC LIMIT 300"
            )
            .all(s.id)
            .reverse();
        const incidents = db
            .prepare(
                "SELECT id,started_at AS time,resolved_at AS resolvedAt,cause FROM incidents WHERE site_id=? ORDER BY id DESC LIMIT 100"
            )
            .all(s.id);
        return {
            ...s,
            enabled: !!s.enabled,
            responseTime: s.response_time,
            statusCode: s.status_code,
            lastChecked: s.last_checked,
            history,
            incidents,
        };
    });
}

app.get("/api/health", (req, res) =>
    res.json({
        status: "ok",
        app: "PulseWatch",
        version: "2.0.0",
        timestamp: new Date().toISOString(),
        checking,
    })
);

app.use("/api", (req, res, next) => {
    if (req.path.startsWith("/auth/")) return next();
    auth(req, res, next);
});

app.post("/api/test-email", async (req, res) => {
  try {
    const nodemailer = require("nodemailer");

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 465),
      secure: process.env.SMTP_SECURE === "true",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    const info = await transporter.sendMail({
      from: process.env.ALERT_EMAIL_FROM || process.env.SMTP_USER,
      to: process.env.ALERT_EMAIL_TO,
      subject: "[PulseWatch] Test Notification",
      text: "PulseWatch email notifications are working."
    });

    transporter.close();

    console.log("Test email sent:", info.messageId);

    res.json({ success: true, messageId: info.messageId });

  } catch (error) {
    console.error("Test email failed:", error);

    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get("/api/overview", (req, res) => {
    const total = db.prepare("SELECT COUNT(*) n FROM sites").get().n;
    const up = db.prepare("SELECT COUNT(*) n FROM sites WHERE status='up'").get().n;
    const down = db.prepare("SELECT COUNT(*) n FROM sites WHERE status='down'").get().n;
    const avg = db.prepare("SELECT ROUND(AVG(response_time)) n FROM sites WHERE response_time IS NOT NULL").get().n;
    res.json({
        total,
        up,
        down,
        pending: total - up - down,
        averageResponseTime: avg || null,
    });
});

app.get("/api/sites", (req, res) => res.json(getSites()));

app.post("/api/sites", rateLimit(20, 60000), async (req, res) => {
    try {
        const name = String(req.body.name || "").trim(),
            raw = String(req.body.url || "").trim();
        if (!name || name.length > 80) return res.status(400).json({ error: "Name must contain 1 to 80 characters." });
        const url = await parseAndValidate(raw);
        const id = crypto.randomUUID();
        db.prepare("INSERT INTO sites(id,name,url,created_at) VALUES(?,?,?,?)").run(
            id,
            name,
            url.href,
            new Date().toISOString()
        );
        const site = db.prepare("SELECT * FROM sites WHERE id=?").get(id);
        const result = await performCheck(site);
        res.status(201).json({ id, name, url: url.href, ...result, history: [], incidents: [] });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

app.post("/api/sites/:id/check", async (req, res) => {
    const s = db.prepare("SELECT * FROM sites WHERE id=?").get(req.params.id);
    if (!s) return res.status(404).json({ error: "Website not found." });
    const result = await performCheck(s);
    res.json({ id: s.id, name: s.name, url: s.url, ...result });
});

app.patch("/api/sites/:id", async (req, res) => {
    try {
        const s = db.prepare("SELECT * FROM sites WHERE id=?").get(req.params.id);

        if (!s) {
            return res.status(404).json({
                error: "Website not found.",
            });
        }

        const name = req.body.name === undefined ? s.name : String(req.body.name).trim();

        if (!name || name.length > 80) {
            return res.status(400).json({
                error: "Name must contain 1 to 80 characters.",
            });
        }

        // Validate a new URL before updating the database.
        let url = s.url;

        if (req.body.url !== undefined) {
            const parsed = await parseAndValidate(String(req.body.url).trim());
            url = parsed.href;
        }

        const enabled = req.body.enabled === undefined ? s.enabled : req.body.enabled ? 1 : 0;

        try {
            db.prepare(
                `
        UPDATE sites
        SET name=?, url=?, enabled=?
        WHERE id=?
      `
            ).run(name, url, enabled, req.params.id);
        } catch (e) {
            if (e.message.includes("UNIQUE constraint failed")) {
                return res.status(409).json({
                    error: "This website URL is already being monitored.",
                });
            }
            throw e;
        }

        // Immediately check if the URL has changed.
        if (url !== s.url && enabled) {
            const updated = db.prepare("SELECT * FROM sites WHERE id=?").get(req.params.id);

            const result = await performCheck(updated);

            return res.json({
                success: true,
                ...result,
            });
        }

        res.json({ success: true });
    } catch (e) {
        res.status(400).json({
            error: e.message,
        });
    }
});
 
app.delete("/api/sites/:id", (req, res) => {
    const r = db.prepare("DELETE FROM sites WHERE id=?").run(req.params.id);
    if (!r.changes) return res.status(404).json({ error: "Website not found." });
    res.json({ success: true });
});

app.get("/api/sites/:id/reports", (req, res) => {
    const s = db.prepare("SELECT id FROM sites WHERE id=?").get(req.params.id);
    if (!s) return res.status(404).json({ error: "Website not found." });
    const since = new Date(Date.now() - 30 * 86400000).toISOString();
    const stats = db
        .prepare(
            "SELECT COUNT(*) total,SUM(CASE WHEN status='up' THEN 1 ELSE 0 END) up,ROUND(AVG(response_time)) avgResponse,MAX(response_time) maxResponse FROM checks WHERE site_id=? AND checked_at>=?"
        )
        .get(req.params.id, since);
    res.json({
        periodDays: 30,
        checks: stats.total,
        uptime: stats.total ? Number(((stats.up / stats.total) * 100).toFixed(3)) : null,
        averageResponseTime: stats.avgResponse,
        maxResponseTime: stats.maxResponse,
    });
});

app.get("/api/incidents", (req, res) =>
    res.json(
        db
            .prepare(
                "SELECT i.*,s.name,s.url FROM incidents i JOIN sites s ON s.id=i.site_id ORDER BY i.id DESC LIMIT 200"
            )
            .all()
    )
);

app.use("/api", (req, res) => res.status(404).json({ error: "API endpoint not found." }));

app.use(
    express.static(path.join(__dirname, "public"), {
        index: false,
        etag: true,
        maxAge: "1h",
    })
);

app.get("/{*splat}", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

const server = app.listen(PORT, "0.0.0.0", () => {
    console.log(`PulseWatch v2 listening on ${PORT}`);
    runChecks();
});

const scheduler = setInterval(runChecks, INTERVAL);

scheduler.unref();

function shutdown() {
    clearInterval(scheduler);
    server.close(() => {
        db.close();
        process.exit(0);
    });
    setTimeout(() => process.exit(1), 10000).unref();
}

process.on("SIGTERM", shutdown);

process.on("SIGINT", shutdown);

// const nodemailer = require("nodemailer");

// const mailer = nodemailer.createTransport({
//     host: "smtp.hostinger.com",
//     port: 587,
//     secure: false,
//     requireTLS: true,
//     auth: {
//         user: process.env.SMTP_USER.trim(),
//         pass: process.env.SMTP_PASS
//     }
// });

// mailer.verify()
//     .then(() => console.log("SMTP AUTHENTICATION SUCCESS"))
//     .catch(err => console.error("SMTP AUTH ERROR:", err));