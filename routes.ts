import type { Express } from "express";
import { createServer, type Server } from "node:http";
import { db } from "./db";
import { profiles, conversations, messages, posts, jobs, reels, products, orders, subscriptionSettings, courses, courseChapters, courseVideos, courseEnrollments, dubbedVideos, ads, liveChatMessages, liveClasses, courseNotices, sessions, payments, appSettings } from "@shared/schema";
import { eq, or, and, desc, gt, lt } from "drizzle-orm";
import { randomUUID } from "crypto";
import multer from "multer";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import Razorpay from "razorpay";
import twilio from "twilio";
import { Storage } from "@google-cloud/storage";

const GCS_BUCKET = process.env.GCS_BUCKET;
let gcsStorage: Storage | null = null;
if (process.env.GCS_SERVICE_ACCOUNT_KEY) {
  try {
    const credentials = JSON.parse(process.env.GCS_SERVICE_ACCOUNT_KEY);
    gcsStorage = new Storage({ credentials, projectId: credentials.project_id });
    console.log(`[GCS] Initialized with bucket: ${GCS_BUCKET || 'not set'}`);
  } catch (err) {
    console.error("[GCS] Failed to initialize:", err);
  }
}

const googleAuthTokens = new Map<string, { email: string; name: string; createdAt: number }>();

function getGoogleClientSecret(): string | undefined {
  const raw = process.env.GOOGLE_CLIENT_SECRET;
  if (!raw) return undefined;
  try {
    const parsed = JSON.parse(raw);
    if (parsed?.web?.client_secret) return parsed.web.client_secret;
    if (parsed?.installed?.client_secret) return parsed.installed.client_secret;
  } catch { }
  return raw;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of googleAuthTokens) {
    if (now - val.createdAt > 5 * 60 * 1000) googleAuthTokens.delete(key);
  }
}, 60000);

const uploadsDir = path.resolve(process.cwd(), "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const BUNNY_STORAGE_API_KEY = process.env.BUNNY_STORAGE_API_KEY || '';
const BUNNY_STORAGE_ZONE_NAME = process.env.BUNNY_STORAGE_ZONE_NAME || '';
const BUNNY_STORAGE_REGION = process.env.BUNNY_STORAGE_REGION || 'sg';
const BUNNY_STORAGE_ENDPOINT = BUNNY_STORAGE_REGION === 'de'
  ? 'https://storage.bunnycdn.com'
  : `https://${BUNNY_STORAGE_REGION}.storage.bunnycdn.com`;
const BUNNY_CDN_URL = `https://Mobistorage.b-cdn.net`;
const bunnyAvailable = !!(BUNNY_STORAGE_API_KEY && BUNNY_STORAGE_ZONE_NAME);

if (bunnyAvailable) {
  console.log(`[Bunny] Storage initialized: zone=${BUNNY_STORAGE_ZONE_NAME}, region=${BUNNY_STORAGE_REGION}`);
} else {
  console.log('[Bunny] Missing BUNNY_STORAGE_API_KEY or BUNNY_STORAGE_ZONE_NAME, using local disk storage');
}

async function uploadToStorage(buffer: Buffer, filename: string): Promise<string> {
  // Prefer GCS if configured
  if (gcsStorage && GCS_BUCKET) {
    try {
      const bucket = gcsStorage.bucket(GCS_BUCKET);
      const file = bucket.file(filename);
      await file.save(buffer, {
        resumable: false,
        metadata: { contentType: filename.endsWith('.png') ? 'image/png' : 'image/jpeg' }
      });
      console.log(`[GCS] Uploaded: ${filename}`);
      return `https://storage.googleapis.com/${GCS_BUCKET}/${filename}`;
    } catch (error) {
      console.error("[GCS] Upload failed:", error);
    }
  }

  if (bunnyAvailable) {
    try {
      const url = `${BUNNY_STORAGE_ENDPOINT}/${BUNNY_STORAGE_ZONE_NAME}/${filename}`;
      const response = await fetch(url, {
        method: 'PUT',
        headers: {
          'AccessKey': BUNNY_STORAGE_API_KEY,
          'Content-Type': 'application/octet-stream',
        },
        body: new Uint8Array(buffer),
      });
      if (!response.ok) {
        throw new Error(`Bunny upload failed: ${response.status} ${response.statusText}`);
      }
      console.log(`[Bunny] Uploaded: ${filename}`);
      return `${BUNNY_CDN_URL}/${filename}`;
    } catch (error) {
      console.error("[Bunny] Upload failed, falling back to local:", error);
    }
  }
  const localFilename = filename.replace(/^(images|videos)\//, "");
  const filePath = path.join(uploadsDir, localFilename);
  fs.writeFileSync(filePath, buffer);
  return `/uploads/${localFilename}`;
}

async function uploadStreamToStorage(
  readStream: NodeJS.ReadableStream,
  filename: string,
  contentType: string
): Promise<string> {
  // Prefer GCS if configured
  if (gcsStorage && GCS_BUCKET) {
    try {
      const bucket = gcsStorage.bucket(GCS_BUCKET);
      const file = bucket.file(filename);
      const stream = file.createWriteStream({
        resumable: true,
        metadata: { contentType }
      });

      return new Promise((resolve, reject) => {
        readStream.pipe(stream)
          .on('error', (err) => reject(err))
          .on('finish', () => {
            console.log(`[GCS] Stream uploaded: ${filename}`);
            resolve(`https://storage.googleapis.com/${GCS_BUCKET}/${filename}`);
          });
      });
    } catch (error) {
      console.error("[GCS] Stream upload failed:", error);
    }
  }

  if (bunnyAvailable) {
    const chunks: Buffer[] = [];
    for await (const chunk of readStream) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    const buffer = Buffer.concat(chunks);
    const url = `${BUNNY_STORAGE_ENDPOINT}/${BUNNY_STORAGE_ZONE_NAME}/${filename}`;
    const response = await fetch(url, {
      method: 'PUT',
      headers: {
        'AccessKey': BUNNY_STORAGE_API_KEY,
        'Content-Type': 'application/octet-stream',
      },
      body: new Uint8Array(buffer),
    });
    if (!response.ok) {
      throw new Error(`Bunny stream upload failed: ${response.status} ${response.statusText}`);
    }
    console.log(`[Bunny] Stream uploaded: ${filename} (${buffer.length} bytes)`);
    return `${BUNNY_CDN_URL}/${filename}`;
  }
  throw new Error("GCS and Bunny.net not available for stream upload");
}

const diskStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname) || ".jpg";
    cb(null, `${randomUUID()}${ext}`);
  },
});

const memStorage = multer.memoryStorage();

const upload = multer({
  storage: memStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only image files are allowed"));
    }
  },
});


const otpStore = new Map<string, { otp: string; expiresAt: number }>();

function sanitizeImageUrls(images: string[]): string[] {
  if (!Array.isArray(images)) return [];
  return images.filter(url => {
    if (typeof url !== 'string') return false;
    if (url.startsWith('file://') || url.startsWith('content://') || url.startsWith('data:')) return false;
    return url.startsWith('http://') || url.startsWith('https://') || url.startsWith('/uploads/') || url.startsWith('/api/files/') || url.startsWith('/api/gcs/');
  });
}

function sanitizeImageUrl(url: string): string {
  if (typeof url !== 'string') return '';
  if (url.startsWith('file://') || url.startsWith('content://') || url.startsWith('data:')) return '';
  return url;
}

function generateOTP(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendWhatsAppOTP(phone: string, otp: string): Promise<boolean> {
  const accountSid = process.env.TWILIO_ACCOUNT_SID;
  const authToken = process.env.TWILIO_AUTH_TOKEN;
  const twilioPhone = process.env.TWILIO_PHONE_NUMBER;

  if (!accountSid || !authToken || !twilioPhone) {
    console.log(`[OTP] Twilio credentials not set. OTP for ${phone}: ${otp}`);
    return false;
  }

  const formattedPhone = phone.startsWith("+") ? phone : `+91${phone.replace(/^91/, "")}`;
  const client = twilio(accountSid, authToken);

  try {
    console.log(`[OTP] Sending WhatsApp OTP to ${formattedPhone}`);
    const message = await client.messages.create({
      body: `Your Mobi verification code is: ${otp}. Valid for 5 minutes. Do not share this code with anyone.`,
      from: `whatsapp:${twilioPhone}`,
      to: `whatsapp:${formattedPhone}`,
    });
    console.log(`[OTP] WhatsApp OTP sent successfully, SID: ${message.sid}`);
    return true;
  } catch (waError: any) {
    console.warn(`[OTP] WhatsApp failed: ${waError?.message}. Falling back to SMS...`);
    try {
      const smsMessage = await client.messages.create({
        body: `Your Mobi verification code is: ${otp}. Valid for 5 minutes. Do not share this code with anyone.`,
        from: twilioPhone,
        to: formattedPhone,
      });
      console.log(`[OTP] SMS fallback sent successfully, SID: ${smsMessage.sid}`);
      return true;
    } catch (smsError: any) {
      console.error("[OTP] Both WhatsApp and SMS failed:", smsError?.message || smsError);
      return false;
    }
  }
}

export async function registerRoutes(app: Express): Promise<Server> {
  // ========== File serving ==========
  app.use("/uploads", (await import("express")).default.static(uploadsDir));

  async function proxyBunnyFile(folder: string, filename: string, res: any) {
    if (!bunnyAvailable) {
      return res.status(404).json({ success: false, message: "Storage not available" });
    }
    const storageUrl = `${BUNNY_STORAGE_ENDPOINT}/${BUNNY_STORAGE_ZONE_NAME}/${folder}/${filename}`;
    const response = await fetch(storageUrl, {
      headers: { 'AccessKey': BUNNY_STORAGE_API_KEY },
    });
    if (!response.ok) {
      return res.status(response.status).json({ success: false, message: "File not found" });
    }
    const ext = path.extname(filename).toLowerCase();
    const mimeTypes: Record<string, string> = {
      '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
      '.gif': 'image/gif', '.webp': 'image/webp', '.mp4': 'video/mp4',
      '.mov': 'video/quicktime', '.webm': 'video/webm',
    };
    res.set('Content-Type', mimeTypes[ext] || 'application/octet-stream');
    res.set('Cache-Control', 'public, max-age=86400');
    const arrayBuffer = await response.arrayBuffer();
    res.send(Buffer.from(arrayBuffer));
  }

  app.get("/api/gcs/:folder/:filename", async (req, res) => {
    try {
      const { folder, filename } = req.params;
      if (!folder || !filename) {
        return res.status(404).json({ success: false, message: "File not found" });
      }
      return proxyBunnyFile(folder, filename, res);
    } catch (error) {
      console.error("[Files] Serve error:", error);
      return res.status(500).json({ success: false, message: "Failed to retrieve file" });
    }
  });

  app.get("/api/gcs-url/:folder/:filename", async (req, res) => {
    try {
      const { folder, filename } = req.params;
      if (!folder || !filename) {
        return res.status(404).json({ success: false, message: "File not found" });
      }
      if (bunnyAvailable) {
        return res.json({ url: `${BUNNY_CDN_URL}/${folder}/${filename}` });
      }
      return res.status(404).json({ success: false, message: "Failed to get URL" });
    } catch (error) {
      console.error("[Files] URL error:", error);
      return res.status(500).json({ success: false, message: "Failed to get URL" });
    }
  });

  app.get("/api/files/:folder/:filename", async (req, res) => {
    try {
      const { folder, filename } = req.params;
      if (!folder || !filename) {
        return res.status(400).json({ success: false, message: "File path required" });
      }
      return proxyBunnyFile(folder, filename, res);
    } catch (error) {
      console.error("[Files] Download error:", error);
      return res.status(500).json({ success: false, message: "Failed to retrieve file" });
    }
  });

  app.post("/api/upload", upload.single("image"), async (req, res) => {
    try {
      if (!req.file) {
        console.log("[Upload] No file received. Headers:", JSON.stringify(req.headers['content-type']));
        return res.status(400).json({ success: false, message: "No image file provided" });
      }
      const ext = path.extname(req.file.originalname) || ".jpg";
      const storageName = `images/${randomUUID()}${ext}`;
      const imageUrl = await uploadToStorage(req.file.buffer, storageName);
      console.log(`[Upload] Image saved: ${imageUrl} (${req.file.size} bytes)`);
      return res.json({ success: true, url: imageUrl });
    } catch (error) {
      console.error("[Upload] Error:", error);
      return res.status(500).json({ success: false, message: "Upload failed" });
    }
  });

  app.post("/api/upload-base64", async (req, res) => {
    try {
      const { base64, mimeType } = req.body;
      if (!base64) {
        return res.status(400).json({ success: false, message: "No image data provided" });
      }
      const ext = (mimeType || "image/jpeg").includes("png") ? ".png" : ".jpg";
      const storageName = `images/${randomUUID()}${ext}`;
      const buffer = Buffer.from(base64, "base64");
      const imageUrl = await uploadToStorage(buffer, storageName);
      console.log(`[Upload] Base64 image saved: ${imageUrl} (${buffer.length} bytes)`);
      return res.json({ success: true, url: imageUrl });
    } catch (error) {
      console.error("[Upload] Base64 error:", error);
      return res.status(500).json({ success: false, message: "Upload failed" });
    }
  });

  // ========== OTP routes ==========
  app.post("/api/otp/send", async (req, res) => {
    try {
      const { phone } = req.body;
      if (!phone || typeof phone !== "string" || phone.length < 10) {
        return res.status(400).json({ success: false, message: "Valid phone number is required" });
      }

      const cleanPhone = phone.replace(/\D/g, "");
      const otp = generateOTP();

      otpStore.set(cleanPhone, {
        otp,
        expiresAt: Date.now() + 5 * 60 * 1000,
      });

      const sent = await sendWhatsAppOTP(cleanPhone, otp);

      console.log(`[OTP] Generated for ${cleanPhone}: ${otp} | Sent: ${sent}`);

      return res.json({
        success: true,
        message: sent ? "OTP sent via WhatsApp" : "OTP generated",
        sent,
      });
    } catch (error) {
      console.error("[OTP] Send error:", error);
      return res.status(500).json({ success: false, message: "Failed to send OTP" });
    }
  });

  app.post("/api/otp/verify", async (req, res) => {
    try {
      const { phone, otp } = req.body;
      if (!phone || !otp) {
        return res.status(400).json({ success: false, message: "Phone and OTP are required" });
      }

      const cleanPhone = phone.replace(/\D/g, "");
      const stored = otpStore.get(cleanPhone);

      if (!stored) {
        return res.status(400).json({ success: false, message: "OTP not found. Please request a new one." });
      }

      if (Date.now() > stored.expiresAt) {
        otpStore.delete(cleanPhone);
        return res.status(400).json({ success: false, message: "OTP has expired. Please request a new one." });
      }

      if (stored.otp !== otp) {
        return res.status(400).json({ success: false, message: "Invalid OTP. Please try again." });
      }

      otpStore.delete(cleanPhone);

      const sessionToken = randomUUID();
      await db.delete(sessions).where(eq(sessions.phone, cleanPhone));
      await db.insert(sessions).values({
        phone: cleanPhone,
        sessionToken,
      });

      return res.json({ success: true, message: "Phone number verified successfully", sessionToken });
    } catch (error) {
      console.error("[OTP] Verify error:", error);
      return res.status(500).json({ success: false, message: "Verification failed" });
    }
  });

  app.post("/api/session/validate", async (req, res) => {
    try {
      const { sessionToken, phone } = req.body;
      if (!sessionToken || !phone) {
        return res.json({ valid: false });
      }
      const cleanPhone = phone.replace(/\D/g, "");
      const result = await db.select().from(sessions).where(
        and(eq(sessions.sessionToken, sessionToken), eq(sessions.phone, cleanPhone))
      );
      return res.json({ valid: result.length > 0 });
    } catch (error) {
      console.error("[Session] Validate error:", error);
      return res.json({ valid: false });
    }
  });

  function sendGoogleErrorPage(res: any, errorMsg: string) {
    console.error("[Google Auth] Error:", errorMsg);
    return res.status(400).send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign-in Error</title>
<style>body{background:#0D0D0F;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;font-family:system-ui,-apple-system,sans-serif}
.c{text-align:center;padding:24px}h2{color:#FF6B35;margin:0 0 12px}p{color:#aaa;margin:0 0 20px;font-size:15px}
.sub{color:#666;font-size:13px}</style></head>
<body><div class="c">
<h2>Sign-in Failed</h2>
<p>${errorMsg}</p>
<p class="sub">Please go back to the Mobi app and try again</p>
</div></body></html>`);
  }

  // ========== Google auth return URL registration ==========
  const googleReturnUrls = new Map<string, string>();

  app.post("/api/auth/google/set-return-url", (req, res) => {
    const { token, returnUrl } = req.body;
    if (token && returnUrl) {
      googleReturnUrls.set(token, returnUrl);
      console.log("[Google Auth] Stored return URL for token:", token.substring(0, 8), "url:", returnUrl.substring(0, 80));
    }
    return res.json({ success: true });
  });

  // ========== Google OAuth callback ==========
  app.get("/api/auth/google/callback", async (req, res) => {
    try {
      const { code, state, error: googleError } = req.query;
      console.log("[Google Auth] Callback received, code:", !!code, "state:", !!state, "error:", googleError);

      if (googleError) {
        return sendGoogleErrorPage(res, `Google returned error: ${googleError}`);
      }

      if (!code) {
        return sendGoogleErrorPage(res, "No authorization code received from Google.");
      }

      const clientId = process.env.EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID;
      const clientSecret = getGoogleClientSecret();

      console.log("[Google Auth] clientId:", clientId);
      console.log("[Google Auth] clientSecret length:", clientSecret?.length, "starts:", clientSecret?.substring(0, 7));

      if (!clientId || !clientSecret) {
        return sendGoogleErrorPage(res, "Google OAuth is not configured on the server.");
      }

      const devDomain = process.env.REPLIT_DOMAINS?.split(",")[0] || process.env.REPLIT_DEV_DOMAIN || "localhost";
      const redirectUri = `https://${devDomain}/api/auth/google/callback`;
      console.log("[Google Auth] Using redirect_uri:", redirectUri);

      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code: code as string,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
          grant_type: "authorization_code",
        }).toString(),
      });

      const tokenData = await tokenRes.json() as any;
      console.log("[Google Auth] Token exchange status:", tokenRes.status, "has access_token:", !!tokenData.access_token);

      if (!tokenData.access_token) {
        console.error("[Google Auth] Token exchange failed:", JSON.stringify(tokenData));
        return sendGoogleErrorPage(res, tokenData.error_description || "Failed to authenticate with Google. The redirect URI may not match.");
      }

      const userInfoRes = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });
      const userInfo = await userInfoRes.json() as any;

      if (!userInfo.email) {
        return sendGoogleErrorPage(res, "Could not get email from your Google account.");
      }

      const email = userInfo.email;
      const name = userInfo.name || '';
      console.log("[Google Auth] Success for email:", email);

      let clientToken = randomUUID();
      let returnUrl = '';
      try {
        if (state) {
          const safeState = (state as string).replace(/ /g, '+');
          const stateStr = Buffer.from(safeState, 'base64').toString('utf-8');
          const stateObj = JSON.parse(stateStr);
          if (stateObj.token) clientToken = stateObj.token;
          if (stateObj.returnUrl) returnUrl = stateObj.returnUrl;
        }
      } catch (e) {
        console.error("[Google Auth] State parse error:", e);
      }

      if (!returnUrl && googleReturnUrls.has(clientToken)) {
        returnUrl = googleReturnUrls.get(clientToken)!;
        googleReturnUrls.delete(clientToken);
        console.log("[Google Auth] Got return URL from pre-registered map:", returnUrl.substring(0, 80));
      }
      googleAuthTokens.set(clientToken, { email, name, createdAt: Date.now() });

      if (returnUrl) {
        const separator = returnUrl.includes('?') ? '&' : '?';
        const deepLink = `${returnUrl}${separator}email=${encodeURIComponent(email)}&name=${encodeURIComponent(name)}`;
        console.log("[Google Auth] Redirecting to deep link:", deepLink);
        return res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Returning to Mobi...</title>
<style>body{background:#0D0D0F;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;font-family:system-ui}
.c{text-align:center;padding:24px}h2{color:#FF6B35;margin:0 0 12px}p{color:#ccc;margin:8px 0}
.spinner{width:40px;height:40px;border:4px solid #333;border-top:4px solid #FF6B35;border-radius:50%;animation:spin 1s linear infinite;margin:20px auto}
@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}</style>
</head><body><div class="c">
<div class="spinner"></div>
<h2>Returning to Mobi...</h2>
<p>If the app doesn't open automatically,<br>tap the button below.</p>
<a href="${deepLink}" style="display:inline-block;margin-top:20px;padding:14px 32px;background:#FF6B35;color:#fff;text-decoration:none;border-radius:8px;font-size:16px;font-weight:600">Open Mobi App</a>
</div>
<script>
setTimeout(function(){window.location.href="${deepLink}"},500);
setTimeout(function(){window.location.href="${deepLink}"},2000);
</script>
</body></html>`);
      }

      return res.redirect(`/api/auth/google/success?token=${clientToken}`);
    } catch (error) {
      console.error("[Google Auth] Callback error:", error);
      return sendGoogleErrorPage(res, "An unexpected error occurred during sign-in.");
    }
  });

  // ========== Google auth check ==========
  app.get("/api/auth/google/success", (req, res) => {
    const { token } = req.query;
    if (!token || !googleAuthTokens.has(token as string)) {
      return res.status(400).send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{background:#0D0D0F;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;font-family:system-ui}
.c{text-align:center}a{color:#FF6B35}</style></head>
<body><div class="c"><p>Session expired. Please try again.</p><a href="/">Go back</a></div></body></html>`);
    }

    return res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Signed In</title>
<style>body{background:#0D0D0F;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;font-family:system-ui,-apple-system,sans-serif}
.c{text-align:center;padding:24px}.icon{font-size:56px;margin-bottom:16px;color:#FF6B35}
h2{margin:0 0 12px;font-size:24px;color:#FF6B35}p{color:#ccc;margin:0 0 8px;font-size:16px;line-height:1.5}
.btn{display:inline-block;margin-top:24px;padding:16px 40px;background:#FF6B35;color:#fff;text-decoration:none;border-radius:12px;font-size:18px;font-weight:700}
.sub{color:#888;font-size:13px;margin-top:20px}</style>
</head>
<body><div class="c">
<div class="icon">&#10003;</div>
<h2>Signed in successfully!</h2>
<p>Now switch back to the Mobi app.<br>Your sign-in will complete automatically.</p>
<p style="color:#FF6B35;font-size:18px;font-weight:700;margin-top:24px">Swipe up from the bottom<br>and tap Expo Go in recent apps</p>
<p class="sub">The app will detect your sign-in<br>and continue automatically</p>
</div></body></html>`);
  });

  app.get("/api/auth/google/done", (req, res) => {
    const { email, name: gname } = req.query;
    return res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign-in Successful</title>
<style>body{background:#0D0D0F;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;font-family:system-ui,-apple-system,sans-serif}
.c{text-align:center;padding:24px}.icon{font-size:48px;margin-bottom:16px;color:#FF6B35}
h2{margin:0 0 8px;font-size:22px;color:#FF6B35}p{color:#aaa;margin:0 0 16px;font-size:15px}</style>
</head>
<body><div class="c">
<div class="icon">&#10003;</div>
<h2>Signed in successfully!</h2>
<p>Returning to Mobi app...</p>
</div></body></html>`);
  });

  app.post("/api/auth/google/process-code", async (req, res) => {
    try {
      const { code, state } = req.body;
      if (!code) {
        return res.status(400).json({ success: false, message: "No authorization code" });
      }

      const clientId = process.env.EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID;
      const clientSecret = getGoogleClientSecret();

      if (!clientId || !clientSecret) {
        return res.status(500).json({ success: false, message: "Google OAuth not configured" });
      }

      const devDomain = process.env.REPLIT_DOMAINS?.split(",")[0] || process.env.REPLIT_DEV_DOMAIN || "localhost";
      const redirectUri = `https://${devDomain}/api/auth/google/callback`;
      console.log("[Google Auth] process-code redirect_uri:", redirectUri);

      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code: code as string,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
          grant_type: "authorization_code",
        }).toString(),
      });

      const tokenData = await tokenRes.json() as any;
      console.log("[Google Auth] process-code token status:", tokenRes.status, "has access_token:", !!tokenData.access_token);

      if (!tokenData.access_token) {
        console.error("[Google Auth] process-code token failed:", JSON.stringify(tokenData));
        return res.status(400).json({ success: false, message: tokenData.error_description || "Token exchange failed" });
      }

      const userInfoRes = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });
      const userInfo = await userInfoRes.json() as any;

      if (!userInfo.email) {
        return res.status(400).json({ success: false, message: "Could not get email" });
      }

      const email = userInfo.email;
      const name = userInfo.name || '';
      console.log("[Google Auth] process-code success:", email);

      let clientToken = randomUUID();
      try {
        if (state) {
          const stateStr = Buffer.from(state as string, 'base64').toString('utf-8');
          const stateObj = JSON.parse(stateStr);
          if (stateObj.token) clientToken = stateObj.token;
        }
      } catch (e) { }
      googleAuthTokens.set(clientToken, { email, name, createdAt: Date.now() });

      return res.json({ success: true, token: clientToken, email, name });
    } catch (error) {
      console.error("[Google Auth] process-code error:", error);
      return res.status(500).json({ success: false, message: "Server error during authentication" });
    }
  });

  app.post("/api/auth/google/exchange", (req, res) => {
    const { token } = req.body;
    if (!token || !googleAuthTokens.has(token as string)) {
      return res.status(400).json({ success: false, message: "Invalid or expired token" });
    }
    const data = googleAuthTokens.get(token as string)!;
    googleAuthTokens.delete(token as string);
    return res.json({ success: true, email: data.email, name: data.name });
  });

  app.post("/api/auth/check-email", async (req, res) => {
    try {
      const { email } = req.body;
      if (!email || typeof email !== "string") {
        return res.status(400).json({ success: false, message: "Email is required" });
      }
      const allProfiles = await db.select().from(profiles);
      const found = allProfiles.find(p => p.email && p.email.toLowerCase() === email.toLowerCase());

      if (found) {
        return res.json({
          success: true,
          exists: true,
          profile: { ...found, skills: JSON.parse(found.skills) },
        });
      }
      return res.json({ success: true, exists: false });
    } catch (error) {
      console.error("[Auth] Check email error:", error);
      return res.status(500).json({ success: false, message: "Failed to check email" });
    }
  });

  // ========== Phone login check ==========
  app.post("/api/auth/check-phone", async (req, res) => {
    try {
      const { phone } = req.body;
      if (!phone || typeof phone !== "string") {
        return res.status(400).json({ success: false, message: "Phone number is required" });
      }
      const cleanPhone = phone.replace(/\D/g, "");
      const allProfiles = await db.select().from(profiles);
      const found = allProfiles.find(p => p.phone.replace(/\D/g, "") === cleanPhone);

      if (found) {
        return res.json({
          success: true,
          exists: true,
          profile: { ...found, skills: JSON.parse(found.skills) },
        });
      }
      return res.json({ success: true, exists: false });
    } catch (error) {
      console.error("[Auth] Check phone error:", error);
      return res.status(500).json({ success: false, message: "Failed to check phone" });
    }
  });

  // ========== Profile routes ==========
  app.post("/api/profiles", async (req, res) => {
    try {
      const { id, name, phone, email, role, skills, city, state, experience, shopName, bio, avatar,
        sellType, teachType, shopAddress, gstNumber, aadhaarNumber, panNumber } = req.body;
      if (!id || !name || !phone || !role) {
        return res.status(400).json({ success: false, message: "Missing required fields" });
      }

      const profileData = {
        name, phone, role,
        email: email || "",
        skills: JSON.stringify(skills || []),
        city: city || "", state: state || "",
        experience: experience || "",
        shopName: shopName || "",
        bio: bio || "",
        avatar: avatar || "",
        sellType: sellType || "",
        teachType: teachType || "",
        shopAddress: shopAddress || "",
        gstNumber: gstNumber || "",
        aadhaarNumber: aadhaarNumber || "",
        panNumber: panNumber || "",
      };

      const existing = await db.select().from(profiles).where(eq(profiles.id, id));
      if (existing.length > 0) {
        await db.update(profiles).set(profileData).where(eq(profiles.id, id));
      } else {
        await db.insert(profiles).values({
          id, ...profileData, createdAt: Date.now(),
        });
      }

      return res.json({ success: true });
    } catch (error) {
      console.error("[Profile] Save error:", error);
      return res.status(500).json({ success: false, message: "Failed to save profile" });
    }
  });

  app.get("/api/profiles", async (_req, res) => {
    try {
      const allProfiles = await db.select().from(profiles);
      const parsed = allProfiles.map(p => ({
        ...p,
        skills: JSON.parse(p.skills),
      }));
      return res.json(parsed);
    } catch (error) {
      console.error("[Profile] List error:", error);
      return res.status(500).json({ success: false, message: "Failed to get profiles" });
    }
  });

  app.get("/api/profiles/:id", async (req, res) => {
    try {
      const result = await db.select().from(profiles).where(eq(profiles.id, req.params.id));
      if (result.length === 0) {
        return res.status(404).json({ success: false, message: "Profile not found" });
      }
      const p = result[0];
      return res.json({ ...p, skills: JSON.parse(p.skills) });
    } catch (error) {
      console.error("[Profile] Get error:", error);
      return res.status(500).json({ success: false, message: "Failed to get profile" });
    }
  });

  app.post("/api/heartbeat", async (req, res) => {
    try {
      const { userId } = req.body;
      if (!userId) return res.status(400).json({ success: false });
      const now = Date.now();
      await db.update(profiles).set({ lastSeen: now }).where(eq(profiles.id, userId));
      return res.json({ success: true, timestamp: now });
    } catch (error) {
      return res.status(500).json({ success: false });
    }
  });

  app.get("/api/stats/online", async (_req, res) => {
    try {
      const allProfiles = await db.select().from(profiles);
      const now = Date.now();
      const ONLINE_THRESHOLD = 5 * 60 * 1000;

      const stats: Record<string, { registered: number; online: number }> = {
        technician: { registered: 0, online: 0 },
        teacher: { registered: 0, online: 0 },
        supplier: { registered: 0, online: 0 },
        job_provider: { registered: 0, online: 0 },
        customer: { registered: 0, online: 0 },
      };

      for (const p of allProfiles) {
        const role = p.role as string;
        if (stats[role]) {
          stats[role].registered++;
          if (p.lastSeen && now - p.lastSeen < ONLINE_THRESHOLD) {
            stats[role].online++;
          }
        }
      }

      return res.json(stats);
    } catch (error) {
      console.error("[Stats] Online stats error:", error);
      return res.status(500).json({ success: false });
    }
  });

  // ========== Subscription Settings routes ==========
  app.get("/api/subscription-settings", async (_req, res) => {
    try {
      const settings = await db.select().from(subscriptionSettings);
      if (settings.length === 0) {
        const defaults = [
          { id: 'sub_technician', role: 'technician', enabled: 0, amount: "99", period: "monthly", commissionPercent: "0" },
          { id: 'sub_teacher', role: 'teacher', enabled: 0, amount: "0", period: "monthly", commissionPercent: "30" },
          { id: 'sub_supplier', role: 'supplier', enabled: 0, amount: "999", period: "monthly", commissionPercent: "0" },
        ];
        for (const d of defaults) {
          await db.insert(subscriptionSettings).values({ ...d, updatedAt: Date.now() });
        }
        return res.json(defaults.map(d => ({ ...d, updatedAt: Date.now() })));
      }
      return res.json(settings);
    } catch (error) {
      console.error("[Subscription] Get error:", error);
      return res.status(500).json({ success: false });
    }
  });

  app.patch("/api/subscription-settings/:role", async (req, res) => {
    try {
      const { role } = req.params;
      const { enabled, amount, period, commissionPercent } = req.body;
      const id = `sub_${role}`;
      const existing = await db.select().from(subscriptionSettings).where(eq(subscriptionSettings.id, id));
      const updateData: any = { updatedAt: Date.now() };
      if (enabled !== undefined) updateData.enabled = enabled;
      if (amount !== undefined) updateData.amount = amount;
      if (period !== undefined) updateData.period = period;
      if (commissionPercent !== undefined) updateData.commissionPercent = commissionPercent;

      if (existing.length > 0) {
        await db.update(subscriptionSettings).set(updateData).where(eq(subscriptionSettings.id, id));
      } else {
        await db.insert(subscriptionSettings).values({
          id, role, enabled: enabled || 0, amount: amount || "0", period: period || "monthly", commissionPercent: commissionPercent || "0", updatedAt: Date.now(),
        });
      }
      return res.json({ success: true });
    } catch (error) {
      console.error("[Subscription] Update error:", error);
      return res.status(500).json({ success: false });
    }
  });

  // ========== Products/Listings routes ==========
  app.get("/api/products", async (req, res) => {
    try {
      const { userId, role } = req.query;
      let allProducts;
      if (userId) {
        allProducts = await db.select().from(products).where(eq(products.userId, userId as string)).orderBy(desc(products.createdAt));
      } else if (role) {
        allProducts = await db.select().from(products).where(eq(products.userRole, role as string)).orderBy(desc(products.createdAt));
      } else {
        allProducts = await db.select().from(products).orderBy(desc(products.createdAt));
      }
      const parsed = allProducts.map(p => ({
        ...p,
        images: JSON.parse(p.images),
        likes: JSON.parse(p.likes),
      }));
      return res.json(parsed);
    } catch (error) {
      console.error("[Products] Get error:", error);
      return res.status(500).json({ success: false });
    }
  });

  app.get("/api/products/:id", async (req, res) => {
    try {
      const result = await db.select().from(products).where(eq(products.id, req.params.id));
      if (result.length === 0) return res.status(404).json({ success: false, message: "Not found" });
      const p = result[0];
      await db.update(products).set({ views: (p.views || 0) + 1 }).where(eq(products.id, req.params.id));
      return res.json({ ...p, images: JSON.parse(p.images), likes: JSON.parse(p.likes), views: (p.views || 0) + 1 });
    } catch (error) {
      return res.status(500).json({ success: false });
    }
  });

  app.post("/api/products", async (req, res) => {
    try {
      const { id, userId, userName, userRole, userAvatar, title, description, price, category, images, city, state, inStock, deliveryInfo, contactPhone, videoUrl } = req.body;
      if (!userId || !title) return res.status(400).json({ success: false, message: "Missing required fields" });
      if (userRole !== 'teacher' && userRole !== 'supplier') return res.status(403).json({ success: false, message: "Only teachers and suppliers can list products" });

      const productId = id || randomUUID();
      const existing = await db.select().from(products).where(eq(products.id, productId));

      if (existing.length > 0) {
        await db.update(products).set({
          title, description, price: price || "0", category: category || "other",
          images: JSON.stringify(images || []), city: city || "", state: state || "",
          inStock: inStock ?? 1, deliveryInfo: deliveryInfo || "", contactPhone: contactPhone || "",
          videoUrl: videoUrl || "",
        }).where(eq(products.id, productId));
      } else {
        await db.insert(products).values({
          id: productId, userId, userName, userRole, userAvatar: userAvatar || "",
          title, description: description || "", price: price || "0", category: category || "other",
          images: JSON.stringify(images || []), city: city || "", state: state || "",
          inStock: inStock ?? 1, deliveryInfo: deliveryInfo || "", contactPhone: contactPhone || "",
          videoUrl: videoUrl || "",
        });
      }
      return res.json({ success: true, id: productId });
    } catch (error) {
      console.error("[Products] Create error:", error);
      return res.status(500).json({ success: false });
    }
  });

  app.delete("/api/products/:id", async (req, res) => {
    try {
      const result = await db.select().from(products).where(eq(products.id, req.params.id));
      if (result.length > 0) {
        try {
          const imgs: string[] = JSON.parse(result[0].images);
          for (const imgUrl of imgs) {
            if (imgUrl.startsWith('/uploads/')) {
              const filePath = path.resolve(process.cwd(), imgUrl.slice(1));
              if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
            }
          }
        } catch (e) { }
      }
      await db.delete(products).where(eq(products.id, req.params.id));
      return res.json({ success: true });
    } catch (error) {
      return res.status(500).json({ success: false });
    }
  });

  app.post("/api/products/:id/like", async (req, res) => {
    try {
      const { userId } = req.body;
      if (!userId) return res.status(400).json({ success: false });
      const result = await db.select().from(products).where(eq(products.id, req.params.id));
      if (result.length === 0) return res.status(404).json({ success: false });
      const likes: string[] = JSON.parse(result[0].likes);
      const idx = likes.indexOf(userId);
      if (idx >= 0) likes.splice(idx, 1); else likes.push(userId);
      await db.update(products).set({ likes: JSON.stringify(likes) }).where(eq(products.id, req.params.id));
      return res.json({ success: true, likes });
    } catch (error) {
      return res.status(500).json({ success: false });
    }
  });

  // ========== Orders routes ==========
  app.post("/api/orders", async (req, res) => {
    try {
      const { productId, productTitle, productPrice, productImage, productCategory, buyerId, buyerName, buyerPhone, buyerCity, buyerState, sellerId, sellerName, sellerRole, quantity, totalAmount, shippingAddress, buyerNotes } = req.body;
      if (!productId || !buyerId || !sellerId) return res.status(400).json({ success: false, message: "Missing required fields" });

      const orderId = randomUUID();
      const now = Date.now();
      await db.insert(orders).values({
        id: orderId, productId, productTitle: productTitle || "", productPrice: productPrice || "0",
        productImage: productImage || "", productCategory: productCategory || "",
        buyerId, buyerName: buyerName || "", buyerPhone: buyerPhone || "",
        buyerCity: buyerCity || "", buyerState: buyerState || "",
        sellerId, sellerName: sellerName || "", sellerRole: sellerRole || "",
        quantity: quantity || 1, totalAmount: totalAmount || "0", status: "pending",
        shippingAddress: shippingAddress || "", buyerNotes: buyerNotes || "", sellerNotes: "",
        updatedAt: now, createdAt: now,
      });
      const created = await db.select().from(orders).where(eq(orders.id, orderId));
      return res.json({ success: true, order: created[0] });
    } catch (error) {
      console.error("[Orders] Create error:", error);
      return res.status(500).json({ success: false, message: "Failed to create order" });
    }
  });

  app.get("/api/orders", async (req, res) => {
    try {
      const { buyerId, sellerId } = req.query;
      let result;
      if (buyerId) {
        result = await db.select().from(orders).where(eq(orders.buyerId, buyerId as string)).orderBy(desc(orders.createdAt));
      } else if (sellerId) {
        result = await db.select().from(orders).where(eq(orders.sellerId, sellerId as string)).orderBy(desc(orders.createdAt));
      } else {
        result = await db.select().from(orders).orderBy(desc(orders.createdAt));
      }
      return res.json(result);
    } catch (error) {
      console.error("[Orders] List error:", error);
      return res.status(500).json({ success: false });
    }
  });

  app.get("/api/orders/:id", async (req, res) => {
    try {
      const result = await db.select().from(orders).where(eq(orders.id, req.params.id));
      if (result.length === 0) return res.status(404).json({ success: false, message: "Order not found" });
      return res.json(result[0]);
    } catch (error) {
      return res.status(500).json({ success: false });
    }
  });

  app.patch("/api/orders/:id/status", async (req, res) => {
    try {
      const { status, sellerNotes } = req.body;
      const validStatuses = ['pending', 'confirmed', 'shipped', 'delivered', 'completed', 'cancelled', 'rejected'];
      if (!status || !validStatuses.includes(status)) return res.status(400).json({ success: false, message: "Invalid status" });

      const result = await db.select().from(orders).where(eq(orders.id, req.params.id));
      if (result.length === 0) return res.status(404).json({ success: false, message: "Order not found" });

      const updateData: any = { status, updatedAt: Date.now() };
      if (sellerNotes !== undefined) updateData.sellerNotes = sellerNotes;
      await db.update(orders).set(updateData).where(eq(orders.id, req.params.id));

      const updated = await db.select().from(orders).where(eq(orders.id, req.params.id));
      return res.json({ success: true, order: updated[0] });
    } catch (error) {
      console.error("[Orders] Status update error:", error);
      return res.status(500).json({ success: false });
    }
  });

  // ========== Posts routes ==========
  app.get("/api/posts", async (_req, res) => {
    try {
      const allPosts = await db.select().from(posts).orderBy(desc(posts.createdAt));
      const parsed = allPosts.map(p => ({
        ...p,
        images: JSON.parse(p.images),
        likes: JSON.parse(p.likes),
        comments: JSON.parse(p.comments),
      }));
      return res.json(parsed);
    } catch (error) {
      console.error("[Posts] List error:", error);
      return res.status(500).json({ success: false, message: "Failed to get posts" });
    }
  });

  app.post("/api/posts", async (req, res) => {
    try {
      const { id, userId, userName, userRole, userAvatar, text: postText, images, videoUrl, category } = req.body;
      if (!userId || !userName || !userRole) {
        return res.status(400).json({ success: false, message: "Missing required fields" });
      }

      const postId = id || randomUUID();
      const now = Date.now();
      const cleanImages = sanitizeImageUrls(images || []);
      const cleanVideoUrl = sanitizeImageUrl(videoUrl || "");
      await db.insert(posts).values({
        id: postId,
        userId,
        userName,
        userRole,
        userAvatar: userAvatar || "",
        text: postText || "",
        images: JSON.stringify(cleanImages),
        videoUrl: cleanVideoUrl,
        category: category || "repair",
        likes: "[]",
        comments: "[]",
        createdAt: now,
      });

      const newPost = {
        id: postId,
        userId,
        userName,
        userRole,
        userAvatar: userAvatar || "",
        text: postText || "",
        images: cleanImages,
        videoUrl: cleanVideoUrl,
        category: category || "repair",
        likes: [],
        comments: [],
        createdAt: now,
      };

      return res.json({ success: true, post: newPost });
    } catch (error) {
      console.error("[Posts] Create error:", error);
      return res.status(500).json({ success: false, message: "Failed to create post" });
    }
  });

  app.patch("/api/posts/:id", async (req, res) => {
    try {
      const { text, images, videoUrl, category } = req.body;
      const updateData: any = {};
      if (text !== undefined) updateData.text = text;
      if (images !== undefined) updateData.images = images;
      if (videoUrl !== undefined) updateData.videoUrl = videoUrl;
      if (category !== undefined) updateData.category = category;
      await db.update(posts).set(updateData).where(eq(posts.id, req.params.id));
      const updated = await db.select().from(posts).where(eq(posts.id, req.params.id));
      return res.json({ success: true, post: updated[0] || null });
    } catch (error) {
      console.error("[Posts] Update error:", error);
      return res.status(500).json({ success: false, message: "Failed to update post" });
    }
  });

  app.delete("/api/posts/:id", async (req, res) => {
    try {
      await db.delete(posts).where(eq(posts.id, req.params.id));
      return res.json({ success: true });
    } catch (error) {
      console.error("[Posts] Delete error:", error);
      return res.status(500).json({ success: false, message: "Failed to delete post" });
    }
  });

  app.post("/api/posts/:id/like", async (req, res) => {
    try {
      const { userId } = req.body;
      if (!userId) return res.status(400).json({ success: false, message: "userId required" });

      const result = await db.select().from(posts).where(eq(posts.id, req.params.id));
      if (result.length === 0) return res.status(404).json({ success: false, message: "Post not found" });

      const post = result[0];
      const currentLikes: string[] = JSON.parse(post.likes);
      const idx = currentLikes.indexOf(userId);
      if (idx >= 0) {
        currentLikes.splice(idx, 1);
      } else {
        currentLikes.push(userId);
      }

      await db.update(posts).set({ likes: JSON.stringify(currentLikes) }).where(eq(posts.id, req.params.id));
      return res.json({ success: true, likes: currentLikes });
    } catch (error) {
      console.error("[Posts] Like error:", error);
      return res.status(500).json({ success: false, message: "Failed to toggle like" });
    }
  });

  app.post("/api/posts/:id/comment", async (req, res) => {
    try {
      const { userId, userName, text: commentText } = req.body;
      if (!userId || !userName || !commentText) {
        return res.status(400).json({ success: false, message: "Missing required fields" });
      }

      const result = await db.select().from(posts).where(eq(posts.id, req.params.id));
      if (result.length === 0) return res.status(404).json({ success: false, message: "Post not found" });

      const post = result[0];
      const currentComments = JSON.parse(post.comments);
      const newComment = {
        id: randomUUID(),
        userId,
        userName,
        text: commentText,
        createdAt: Date.now(),
      };
      currentComments.push(newComment);

      await db.update(posts).set({ comments: JSON.stringify(currentComments) }).where(eq(posts.id, req.params.id));
      return res.json({ success: true, comment: newComment });
    } catch (error) {
      console.error("[Posts] Comment error:", error);
      return res.status(500).json({ success: false, message: "Failed to add comment" });
    }
  });

  // ========== Jobs routes ==========
  app.get("/api/jobs", async (_req, res) => {
    try {
      const allJobs = await db.select().from(jobs).orderBy(desc(jobs.createdAt));
      const parsed = allJobs.map(j => ({
        ...j,
        skills: JSON.parse(j.skills),
      }));
      return res.json(parsed);
    } catch (error) {
      console.error("[Jobs] List error:", error);
      return res.status(500).json({ success: false, message: "Failed to get jobs" });
    }
  });

  app.post("/api/jobs", async (req, res) => {
    try {
      const { id, userId, userName, title, description, city, state, skills, salary, type } = req.body;
      if (!userId || !userName || !title) {
        return res.status(400).json({ success: false, message: "Missing required fields" });
      }

      const jobId = id || randomUUID();
      const now = Date.now();
      await db.insert(jobs).values({
        id: jobId,
        userId,
        userName,
        title,
        description: description || "",
        city: city || "",
        state: state || "",
        skills: JSON.stringify(skills || []),
        salary: salary || "",
        type: type || "full_time",
        createdAt: now,
      });

      const newJob = {
        id: jobId,
        userId,
        userName,
        title,
        description: description || "",
        city: city || "",
        state: state || "",
        skills: skills || [],
        salary: salary || "",
        type: type || "full_time",
        createdAt: now,
      };

      return res.json({ success: true, job: newJob });
    } catch (error) {
      console.error("[Jobs] Create error:", error);
      return res.status(500).json({ success: false, message: "Failed to create job" });
    }
  });

  app.delete("/api/jobs/:id", async (req, res) => {
    try {
      await db.delete(jobs).where(eq(jobs.id, req.params.id));
      return res.json({ success: true });
    } catch (error) {
      console.error("[Jobs] Delete error:", error);
      return res.status(500).json({ success: false, message: "Failed to delete job" });
    }
  });

  // ========== Chat routes ==========
  app.get("/api/conversations/:userId", async (req, res) => {
    try {
      const { userId } = req.params;
      const convos = await db.select().from(conversations)
        .where(or(
          eq(conversations.participant1Id, userId),
          eq(conversations.participant2Id, userId)
        ))
        .orderBy(desc(conversations.lastMessageAt));

      return res.json(convos);
    } catch (error) {
      console.error("[Chat] List conversations error:", error);
      return res.status(500).json({ success: false, message: "Failed to get conversations" });
    }
  });

  app.post("/api/conversations", async (req, res) => {
    try {
      const { participant1Id, participant1Name, participant1Role, participant2Id, participant2Name, participant2Role } = req.body;

      if (!participant1Id || !participant2Id) {
        return res.status(400).json({ success: false, message: "Both participants required" });
      }

      if (participant2Role === 'customer' && participant1Role !== 'customer') {
        return res.status(403).json({ success: false, message: "Only customers can initiate conversations with other customers" });
      }

      if (participant2Role === 'teacher' && participant1Role === 'technician') {
        const now = Date.now();
        const activeEnrollments = await db.select().from(courseEnrollments)
          .where(and(
            eq(courseEnrollments.studentId, participant1Id),
            eq(courseEnrollments.teacherId, participant2Id),
            gt(courseEnrollments.expiresAt, now)
          ));
        if (activeEnrollments.length === 0) {
          return res.status(403).json({ success: false, message: "You need to purchase a course from this teacher before starting a conversation." });
        }
      }

      const existing = await db.select().from(conversations)
        .where(or(
          and(eq(conversations.participant1Id, participant1Id), eq(conversations.participant2Id, participant2Id)),
          and(eq(conversations.participant1Id, participant2Id), eq(conversations.participant2Id, participant1Id))
        ));

      if (existing.length > 0) {
        return res.json({ success: true, conversation: existing[0] });
      }

      const id = randomUUID();
      const now = Date.now();
      const newConvo = {
        id,
        participant1Id, participant1Name, participant1Role,
        participant2Id, participant2Name, participant2Role,
        lastMessage: "",
        lastMessageAt: now,
        createdAt: now,
      };

      await db.insert(conversations).values(newConvo);
      return res.json({ success: true, conversation: newConvo });
    } catch (error) {
      console.error("[Chat] Create conversation error:", error);
      return res.status(500).json({ success: false, message: "Failed to create conversation" });
    }
  });

  app.delete("/api/conversations/:id", async (req, res) => {
    try {
      const { id } = req.params;
      await db.delete(messages).where(eq(messages.conversationId, id));
      await db.delete(conversations).where(eq(conversations.id, id));
      return res.json({ success: true });
    } catch (error) {
      console.error("[Chat] Delete conversation error:", error);
      return res.status(500).json({ success: false, message: "Failed to delete conversation" });
    }
  });

  app.get("/api/messages/:conversationId", async (req, res) => {
    try {
      const { conversationId } = req.params;
      const msgs = await db.select().from(messages)
        .where(eq(messages.conversationId, conversationId))
        .orderBy(messages.createdAt);

      return res.json(msgs);
    } catch (error) {
      console.error("[Chat] Get messages error:", error);
      return res.status(500).json({ success: false, message: "Failed to get messages" });
    }
  });

  app.post("/api/messages", async (req, res) => {
    try {
      const { conversationId, senderId, senderName, text: msgText, image } = req.body;
      console.log(`[Chat] POST /api/messages body: text=${JSON.stringify(msgText)}, image=${JSON.stringify(image)}, senderId=${senderId}`);

      if (!conversationId || !senderId || !senderName) {
        return res.status(400).json({ success: false, message: "Missing required fields" });
      }

      const id = randomUUID();
      const now = Date.now();
      const cleanImage = sanitizeImageUrl(image || "");
      const cleanText = (msgText || "").trim();

      if (!cleanText && !cleanImage) {
        console.log(`[Chat] Skipping empty message from ${senderName} (${senderId})`);
        return res.json({ success: true, message: { id, conversationId, senderId, senderName, text: "", image: "", createdAt: now } });
      }

      const newMsg = {
        id,
        conversationId,
        senderId,
        senderName,
        text: cleanText,
        image: cleanImage,
        createdAt: now,
      };

      await db.insert(messages).values(newMsg);

      const lastMsg = cleanImage ? (cleanText || "Sent an image") : (cleanText || "");
      await db.update(conversations)
        .set({ lastMessage: lastMsg, lastMessageSenderId: senderId, lastMessageAt: now })
        .where(eq(conversations.id, conversationId));

      return res.json({ success: true, message: newMsg });
    } catch (error) {
      console.error("[Chat] Send message error:", error);
      return res.status(500).json({ success: false, message: "Failed to send message" });
    }
  });

  app.get("/api/messages/:conversationId/since/:timestamp", async (req, res) => {
    try {
      const { conversationId, timestamp } = req.params;
      const ts = parseInt(timestamp);
      const msgs = await db.select().from(messages)
        .where(and(
          eq(messages.conversationId, conversationId),
          gt(messages.createdAt, ts)
        ))
        .orderBy(messages.createdAt);

      return res.json(msgs);
    } catch (error) {
      console.error("[Chat] Poll messages error:", error);
      return res.status(500).json({ success: false, message: "Failed to poll messages" });
    }
  });

  // ========== Reels ==========
  app.get("/api/reels", async (_req, res) => {
    try {
      const allReels = await db.select().from(reels).orderBy(desc(reels.createdAt));
      const mapped = allReels.map(r => ({
        ...r,
        likes: JSON.parse(r.likes || "[]"),
        comments: JSON.parse(r.comments || "[]"),
      }));
      return res.json(mapped);
    } catch (error) {
      console.error("[Reels] List error:", error);
      return res.status(500).json({ success: false, message: "Failed to list reels" });
    }
  });

  app.post("/api/reels", async (req, res) => {
    try {
      const { userId, userName, userAvatar, title, description, videoUrl, thumbnailUrl } = req.body;
      if (!userId || !videoUrl) {
        return res.status(400).json({ success: false, message: "userId and videoUrl required" });
      }

      const id = randomUUID();
      const now = Date.now();

      await db.insert(reels).values({
        id,
        userId,
        userName: userName || "",
        userAvatar: userAvatar || "",
        title: title || "",
        description: description || "",
        videoUrl,
        thumbnailUrl: thumbnailUrl || "",
        likes: "[]",
        comments: "[]",
        views: 0,
        createdAt: now,
      });

      const reel = {
        id, userId, userName: userName || "", userAvatar: userAvatar || "",
        title: title || "", description: description || "", videoUrl,
        thumbnailUrl: thumbnailUrl || "", likes: [], comments: [], views: 0, createdAt: now,
      };

      return res.json({ success: true, reel });
    } catch (error) {
      console.error("[Reels] Create error:", error);
      return res.status(500).json({ success: false, message: "Failed to create reel" });
    }
  });

  app.post("/api/reels/:id/like", async (req, res) => {
    try {
      const { id } = req.params;
      const { userId } = req.body;
      if (!userId) return res.status(400).json({ success: false, message: "userId required" });

      const [reel] = await db.select().from(reels).where(eq(reels.id, id));
      if (!reel) return res.status(404).json({ success: false, message: "Reel not found" });

      const likesList: string[] = JSON.parse(reel.likes || "[]");
      const idx = likesList.indexOf(userId);
      if (idx >= 0) likesList.splice(idx, 1);
      else likesList.push(userId);

      await db.update(reels).set({ likes: JSON.stringify(likesList) }).where(eq(reels.id, id));
      return res.json({ success: true, likes: likesList });
    } catch (error) {
      console.error("[Reels] Like error:", error);
      return res.status(500).json({ success: false, message: "Failed to like reel" });
    }
  });

  app.post("/api/reels/:id/comment", async (req, res) => {
    try {
      const { userId, userName, text: commentText } = req.body;
      if (!userId || !userName || !commentText) {
        return res.status(400).json({ success: false, message: "userId, userName, text required" });
      }

      const [reel] = await db.select().from(reels).where(eq(reels.id, req.params.id));
      if (!reel) return res.status(404).json({ success: false, message: "Reel not found" });

      const currentComments = JSON.parse(reel.comments || "[]");
      const newComment = {
        id: randomUUID(),
        userId,
        userName,
        text: commentText,
        createdAt: Date.now(),
      };
      currentComments.push(newComment);

      await db.update(reels).set({ comments: JSON.stringify(currentComments) }).where(eq(reels.id, req.params.id));
      return res.json({ success: true, comment: newComment, comments: currentComments });
    } catch (error) {
      console.error("[Reels] Comment error:", error);
      return res.status(500).json({ success: false, message: "Failed to add comment" });
    }
  });

  app.delete("/api/reels/:id", async (req, res) => {
    try {
      const { id } = req.params;
      await db.delete(reels).where(eq(reels.id, id));
      return res.json({ success: true });
    } catch (error) {
      console.error("[Reels] Delete error:", error);
      return res.status(500).json({ success: false, message: "Failed to delete reel" });
    }
  });

  const diskVideoUpload = multer({
    storage: diskStorage,
    limits: { fileSize: 500 * 1024 * 1024 },
    fileFilter: (_req, file, cb) => {
      if (file.mimetype.startsWith("video/")) {
        cb(null, true);
      } else {
        cb(new Error("Only video files are allowed"));
      }
    },
  });

  app.post("/api/upload-video", (req, res, next) => {
    diskVideoUpload.single("video")(req, res, (err) => {
      if (err) {
        if (err.code === "LIMIT_FILE_SIZE") {
          return res.status(413).json({ success: false, message: "Video file is too large. Maximum size is 500MB." });
        }
        return res.status(400).json({ success: false, message: err.message || "Upload error" });
      }
      next();
    });
  }, async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ success: false, message: "No video file provided" });
      }
      const ext = path.extname(req.file.originalname) || ".mp4";
      const storageName = `videos/${randomUUID()}${ext}`;

      if (bunnyAvailable) {
        const localPath = req.file.path;
        const readStream = fs.createReadStream(localPath);
        const videoUrl = await uploadStreamToStorage(readStream, storageName, req.file.mimetype);
        fs.unlink(localPath, () => { });
        console.log(`[Upload] Video uploaded to Bunny: ${videoUrl} (${req.file.size} bytes)`);
        return res.json({ success: true, url: videoUrl });
      } else {
        const videoUrl = `/uploads/${req.file.filename}`;
        console.log(`[Upload] Video saved locally: ${videoUrl} (${req.file.size} bytes)`);
        return res.json({ success: true, url: videoUrl });
      }
    } catch (error) {
      console.error("[Upload] Video error:", error);
      if (req.file?.path) fs.unlink(req.file.path, () => { });
      return res.status(500).json({ success: false, message: "Video upload failed" });
    }
  });

  // ========== Course routes ==========
  app.get("/api/courses", async (req, res) => {
    try {
      const { teacherId, published } = req.query;
      let allCourses;
      if (teacherId) {
        allCourses = await db.select().from(courses)
          .where(eq(courses.teacherId, teacherId as string))
          .orderBy(desc(courses.createdAt));
      } else if (published === 'true') {
        allCourses = await db.select().from(courses)
          .where(eq(courses.isPublished, 1))
          .orderBy(desc(courses.createdAt));
      } else {
        allCourses = await db.select().from(courses).orderBy(desc(courses.createdAt));
      }
      return res.json(allCourses);
    } catch (error) {
      console.error("[Courses] List error:", error);
      return res.status(500).json({ success: false, message: "Failed to get courses" });
    }
  });

  app.get("/api/courses/:id", async (req, res) => {
    try {
      const [course] = await db.select().from(courses).where(eq(courses.id, req.params.id));
      if (!course) return res.status(404).json({ success: false, message: "Course not found" });

      const chapters = await db.select().from(courseChapters)
        .where(eq(courseChapters.courseId, req.params.id))
        .orderBy(courseChapters.sortOrder);

      const chaptersWithVideos = await Promise.all(chapters.map(async (chapter) => {
        const videos = await db.select().from(courseVideos)
          .where(eq(courseVideos.chapterId, chapter.id))
          .orderBy(courseVideos.sortOrder);
        return { ...chapter, videos };
      }));

      return res.json({ ...course, chapters: chaptersWithVideos });
    } catch (error) {
      console.error("[Courses] Get error:", error);
      return res.status(500).json({ success: false, message: "Failed to get course" });
    }
  });

  app.post("/api/courses", async (req, res) => {
    try {
      const { id, teacherId, teacherName, teacherAvatar, title, description, price, coverImage, category, language, demoDuration, accessDays, isPublished } = req.body;
      if (!teacherId || !title) {
        return res.status(400).json({ success: false, message: "teacherId and title are required" });
      }

      const courseId = id || randomUUID();
      const now = Date.now();

      if (id) {
        const [existing] = await db.select().from(courses).where(eq(courses.id, id));
        if (existing) {
          const updateData: any = {};
          if (title !== undefined) updateData.title = title;
          if (description !== undefined) updateData.description = description;
          if (price !== undefined) updateData.price = price;
          if (coverImage !== undefined) updateData.coverImage = coverImage;
          if (category !== undefined) updateData.category = category;
          if (language !== undefined) updateData.language = language;
          if (demoDuration !== undefined) updateData.demoDuration = demoDuration;
          if (accessDays !== undefined) updateData.accessDays = accessDays;
          if (isPublished !== undefined) updateData.isPublished = isPublished;
          if (teacherName !== undefined) updateData.teacherName = teacherName;
          if (teacherAvatar !== undefined) updateData.teacherAvatar = teacherAvatar;

          await db.update(courses).set(updateData).where(eq(courses.id, id));
          const [updated] = await db.select().from(courses).where(eq(courses.id, id));
          return res.json({ success: true, course: updated });
        }
      }

      await db.insert(courses).values({
        id: courseId,
        teacherId,
        teacherName: teacherName || "",
        teacherAvatar: teacherAvatar || "",
        title,
        description: description || "",
        price: price || "0",
        coverImage: coverImage || "",
        category: category || "course",
        language: language || "hindi",
        demoDuration: demoDuration || 60,
        accessDays: accessDays || 365,
        totalVideos: 0,
        totalDuration: 0,
        enrollmentCount: 0,
        rating: "0",
        isPublished: isPublished || 0,
        createdAt: now,
      });

      const [newCourse] = await db.select().from(courses).where(eq(courses.id, courseId));
      return res.json({ success: true, course: newCourse });
    } catch (error) {
      console.error("[Courses] Create error:", error);
      return res.status(500).json({ success: false, message: "Failed to create course" });
    }
  });

  app.delete("/api/courses/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const videos = await db.select().from(courseVideos).where(eq(courseVideos.courseId, id));
      for (const video of videos) {
        await db.delete(dubbedVideos).where(eq(dubbedVideos.videoId, video.id));
      }
      await db.delete(courseVideos).where(eq(courseVideos.courseId, id));
      await db.delete(courseChapters).where(eq(courseChapters.courseId, id));
      await db.delete(courseEnrollments).where(eq(courseEnrollments.courseId, id));
      await db.delete(dubbedVideos).where(eq(dubbedVideos.courseId, id));
      await db.delete(courses).where(eq(courses.id, id));
      return res.json({ success: true });
    } catch (error) {
      console.error("[Courses] Delete error:", error);
      return res.status(500).json({ success: false, message: "Failed to delete course" });
    }
  });

  app.post("/api/courses/:courseId/chapters", async (req, res) => {
    try {
      const { courseId } = req.params;
      const { title, description, sortOrder } = req.body;
      if (!title) {
        return res.status(400).json({ success: false, message: "Title is required" });
      }

      const id = randomUUID();
      const now = Date.now();
      await db.insert(courseChapters).values({
        id,
        courseId,
        title,
        description: description || "",
        sortOrder: sortOrder || 0,
        createdAt: now,
      });

      const [chapter] = await db.select().from(courseChapters).where(eq(courseChapters.id, id));
      return res.json({ success: true, chapter });
    } catch (error) {
      console.error("[Courses] Create chapter error:", error);
      return res.status(500).json({ success: false, message: "Failed to create chapter" });
    }
  });

  app.put("/api/courses/:courseId/chapters/:chapterId", async (req, res) => {
    try {
      const { chapterId } = req.params;
      const { title, description, sortOrder } = req.body;
      const updateData: any = {};
      if (title !== undefined) updateData.title = title;
      if (description !== undefined) updateData.description = description;
      if (sortOrder !== undefined) updateData.sortOrder = sortOrder;

      await db.update(courseChapters).set(updateData).where(eq(courseChapters.id, chapterId));
      const [updated] = await db.select().from(courseChapters).where(eq(courseChapters.id, chapterId));
      return res.json({ success: true, chapter: updated });
    } catch (error) {
      console.error("[Courses] Update chapter error:", error);
      return res.status(500).json({ success: false, message: "Failed to update chapter" });
    }
  });

  app.delete("/api/courses/:courseId/chapters/:chapterId", async (req, res) => {
    try {
      const { chapterId } = req.params;
      const videos = await db.select().from(courseVideos).where(eq(courseVideos.chapterId, chapterId));
      for (const video of videos) {
        await db.delete(dubbedVideos).where(eq(dubbedVideos.videoId, video.id));
      }
      await db.delete(courseVideos).where(eq(courseVideos.chapterId, chapterId));
      await db.delete(courseChapters).where(eq(courseChapters.id, chapterId));
      return res.json({ success: true });
    } catch (error) {
      console.error("[Courses] Delete chapter error:", error);
      return res.status(500).json({ success: false, message: "Failed to delete chapter" });
    }
  });

  app.post("/api/courses/:courseId/chapters/:chapterId/videos", async (req, res) => {
    try {
      const { courseId, chapterId } = req.params;
      const { title, description, videoUrl, thumbnailUrl, duration, sortOrder, isDemo } = req.body;
      if (!title || !videoUrl) {
        return res.status(400).json({ success: false, message: "Title and videoUrl are required" });
      }

      const id = randomUUID();
      const now = Date.now();
      const videoDuration = duration || 0;

      await db.insert(courseVideos).values({
        id,
        courseId,
        chapterId,
        title,
        description: description || "",
        videoUrl,
        thumbnailUrl: thumbnailUrl || "",
        duration: videoDuration,
        sortOrder: sortOrder || 0,
        isDemo: isDemo || 0,
        createdAt: now,
      });

      const allVideos = await db.select().from(courseVideos).where(eq(courseVideos.courseId, courseId));
      const totalVideos = allVideos.length;
      const totalDuration = allVideos.reduce((sum, v) => sum + (v.duration || 0), 0);
      await db.update(courses).set({ totalVideos, totalDuration }).where(eq(courses.id, courseId));

      const [video] = await db.select().from(courseVideos).where(eq(courseVideos.id, id));
      return res.json({ success: true, video });
    } catch (error) {
      console.error("[Courses] Create video error:", error);
      return res.status(500).json({ success: false, message: "Failed to create video" });
    }
  });

  app.delete("/api/courses/:courseId/videos/:videoId", async (req, res) => {
    try {
      const { courseId, videoId } = req.params;
      await db.delete(dubbedVideos).where(eq(dubbedVideos.videoId, videoId));
      await db.delete(courseVideos).where(eq(courseVideos.id, videoId));

      const allVideos = await db.select().from(courseVideos).where(eq(courseVideos.courseId, courseId));
      const totalVideos = allVideos.length;
      const totalDuration = allVideos.reduce((sum, v) => sum + (v.duration || 0), 0);
      await db.update(courses).set({ totalVideos, totalDuration }).where(eq(courses.id, courseId));

      return res.json({ success: true });
    } catch (error) {
      console.error("[Courses] Delete video error:", error);
      return res.status(500).json({ success: false, message: "Failed to delete video" });
    }
  });

  app.post("/api/courses/:courseId/enroll", async (req, res) => {
    try {
      const { courseId } = req.params;
      const { studentId, studentName, studentPhone, teacherId } = req.body;
      if (!studentId || !studentName) {
        return res.status(400).json({ success: false, message: "studentId and studentName are required" });
      }

      const [course] = await db.select().from(courses).where(eq(courses.id, courseId));
      if (!course) return res.status(404).json({ success: false, message: "Course not found" });

      const existing = await db.select().from(courseEnrollments)
        .where(and(
          eq(courseEnrollments.courseId, courseId),
          eq(courseEnrollments.studentId, studentId)
        ));
      if (existing.length > 0) {
        return res.json({ success: true, enrollment: existing[0], message: "Already enrolled" });
      }

      const now = Date.now();
      const accessDays = course.accessDays || 365;
      const expiresAt = now + accessDays * 24 * 60 * 60 * 1000;
      const id = randomUUID();

      await db.insert(courseEnrollments).values({
        id,
        courseId,
        studentId,
        studentName,
        studentPhone: studentPhone || "",
        teacherId: teacherId || course.teacherId,
        status: "active",
        paymentStatus: "pending",
        expiresAt,
        createdAt: now,
      });

      await db.update(courses).set({ enrollmentCount: (course.enrollmentCount || 0) + 1 }).where(eq(courses.id, courseId));

      const [enrollment] = await db.select().from(courseEnrollments).where(eq(courseEnrollments.id, id));
      return res.json({ success: true, enrollment });
    } catch (error) {
      console.error("[Courses] Enroll error:", error);
      return res.status(500).json({ success: false, message: "Failed to enroll" });
    }
  });

  app.get("/api/enrollments", async (req, res) => {
    try {
      const { studentId, teacherId } = req.query;
      let enrollments;
      if (studentId) {
        enrollments = await db.select().from(courseEnrollments)
          .where(eq(courseEnrollments.studentId, studentId as string))
          .orderBy(desc(courseEnrollments.createdAt));
      } else if (teacherId) {
        enrollments = await db.select().from(courseEnrollments)
          .where(eq(courseEnrollments.teacherId, teacherId as string))
          .orderBy(desc(courseEnrollments.createdAt));
      } else {
        enrollments = await db.select().from(courseEnrollments).orderBy(desc(courseEnrollments.createdAt));
      }
      return res.json(enrollments);
    } catch (error) {
      console.error("[Enrollments] List error:", error);
      return res.status(500).json({ success: false, message: "Failed to get enrollments" });
    }
  });

  app.get("/api/enrollments/check", async (req, res) => {
    try {
      const { courseId, studentId } = req.query;
      if (!courseId || !studentId) {
        return res.status(400).json({ success: false, message: "courseId and studentId are required" });
      }

      const existing = await db.select().from(courseEnrollments)
        .where(and(
          eq(courseEnrollments.courseId, courseId as string),
          eq(courseEnrollments.studentId, studentId as string)
        ));

      if (existing.length > 0) {
        return res.json({ enrolled: true, enrollment: existing[0] });
      }
      return res.json({ enrolled: false, enrollment: null });
    } catch (error) {
      console.error("[Enrollments] Check error:", error);
      return res.status(500).json({ success: false, message: "Failed to check enrollment" });
    }
  });

  // ==================== RAZORPAY PAYMENT ROUTES ====================
  const razorpayKeyId = process.env.RAZORPAY_KEY_ID || '';
  const razorpayKeySecret = process.env.RAZORPAY_KEY_SECRET || '';
  const razorpayAvailable = !!(razorpayKeyId && razorpayKeySecret);

  let razorpayInstance: any = null;
  if (razorpayAvailable) {
    razorpayInstance = new Razorpay({
      key_id: razorpayKeyId,
      key_secret: razorpayKeySecret,
    });
    console.log(`[Razorpay] Payment gateway initialized (key: ${razorpayKeyId.substring(0, 12)}...)`);
  } else {
    console.log('[Razorpay] Missing RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET');
  }

  app.post("/api/payments/create-order", async (req, res) => {
    try {
      if (!razorpayAvailable || !razorpayInstance) {
        return res.status(503).json({ success: false, message: "Payment gateway not configured" });
      }
      const { courseId, studentId, studentName, studentPhone } = req.body;
      if (!courseId || !studentId || !studentName) {
        return res.status(400).json({ success: false, message: "courseId, studentId, and studentName required" });
      }

      const [course] = await db.select().from(courses).where(eq(courses.id, courseId));
      if (!course) return res.status(404).json({ success: false, message: "Course not found" });

      const existing = await db.select().from(courseEnrollments)
        .where(and(
          eq(courseEnrollments.courseId, courseId),
          eq(courseEnrollments.studentId, studentId)
        ));
      if (existing.length > 0 && existing[0].status === 'active') {
        return res.json({ success: true, alreadyEnrolled: true, enrollment: existing[0] });
      }

      const amountInPaise = Math.round(parseFloat(course.price || '0') * 100);
      if (amountInPaise <= 0) {
        const now = Date.now();
        const accessDays = course.accessDays || 365;
        const expiresAt = now + accessDays * 24 * 60 * 60 * 1000;
        const id = randomUUID();
        await db.insert(courseEnrollments).values({
          id, courseId, studentId, studentName,
          studentPhone: studentPhone || "",
          teacherId: course.teacherId,
          status: "active", paymentStatus: "free", expiresAt, createdAt: now,
        });
        await db.update(courses).set({ enrollmentCount: (course.enrollmentCount || 0) + 1 }).where(eq(courses.id, courseId));
        const [enrollment] = await db.select().from(courseEnrollments).where(eq(courseEnrollments.id, id));
        return res.json({ success: true, free: true, enrollment });
      }

      const options = {
        amount: amountInPaise,
        currency: "INR",
        receipt: `crs_${Date.now()}`,
        notes: {
          courseId, studentId, studentName, courseTitle: course.title, teacherId: course.teacherId,
        },
      };
      const order = await razorpayInstance.orders.create(options);

      const paymentId = randomUUID();
      await db.insert(payments).values({
        id: paymentId,
        razorpayOrderId: order.id,
        courseId, studentId, studentName,
        studentPhone: studentPhone || "",
        teacherId: course.teacherId,
        amount: amountInPaise,
        currency: "INR",
        status: "created",
        createdAt: Date.now(),
      });

      return res.json({
        success: true,
        orderId: order.id,
        amount: amountInPaise,
        currency: "INR",
        keyId: razorpayKeyId,
        courseName: course.title,
        teacherName: course.teacherName,
        paymentRecordId: paymentId,
      });
    } catch (error) {
      console.error("[Razorpay] Create order error:", error);
      return res.status(500).json({ success: false, message: "Failed to create payment order" });
    }
  });

  app.post("/api/payments/verify", async (req, res) => {
    try {
      if (!razorpayAvailable) {
        return res.status(503).json({ success: false, message: "Payment gateway not configured" });
      }
      const { razorpay_order_id, razorpay_payment_id, razorpay_signature, courseId, studentId, studentName, studentPhone } = req.body;
      if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
        return res.status(400).json({ success: false, message: "Payment verification data missing" });
      }

      const body = razorpay_order_id + "|" + razorpay_payment_id;
      const expectedSignature = crypto.createHmac('sha256', razorpayKeySecret).update(body).digest('hex');
      const isValid = expectedSignature === razorpay_signature;

      if (!isValid) {
        await db.update(payments).set({
          status: "failed",
          razorpayPaymentId: razorpay_payment_id,
          razorpaySignature: razorpay_signature,
        }).where(eq(payments.razorpayOrderId, razorpay_order_id));
        return res.status(400).json({ success: false, message: "Payment verification failed - invalid signature" });
      }

      await db.update(payments).set({
        status: "paid",
        razorpayPaymentId: razorpay_payment_id,
        razorpaySignature: razorpay_signature,
      }).where(eq(payments.razorpayOrderId, razorpay_order_id));

      const [course] = await db.select().from(courses).where(eq(courses.id, courseId));
      if (!course) {
        return res.status(404).json({ success: false, message: "Course not found" });
      }

      const existingEnrollment = await db.select().from(courseEnrollments)
        .where(and(
          eq(courseEnrollments.courseId, courseId),
          eq(courseEnrollments.studentId, studentId)
        ));
      if (existingEnrollment.length > 0) {
        await db.update(courseEnrollments).set({
          status: "active",
          paymentStatus: "paid",
        }).where(eq(courseEnrollments.id, existingEnrollment[0].id));
        const [updated] = await db.select().from(courseEnrollments).where(eq(courseEnrollments.id, existingEnrollment[0].id));
        return res.json({ success: true, enrollment: updated });
      }

      const now = Date.now();
      const accessDays = course.accessDays || 365;
      const expiresAt = now + accessDays * 24 * 60 * 60 * 1000;
      const enrollId = randomUUID();

      await db.insert(courseEnrollments).values({
        id: enrollId, courseId, studentId,
        studentName: studentName || "Student",
        studentPhone: studentPhone || "",
        teacherId: course.teacherId,
        status: "active", paymentStatus: "paid", expiresAt, createdAt: now,
      });
      await db.update(courses).set({ enrollmentCount: (course.enrollmentCount || 0) + 1 }).where(eq(courses.id, courseId));
      await db.update(payments).set({ enrollmentId: enrollId }).where(eq(payments.razorpayOrderId, razorpay_order_id));

      const [enrollment] = await db.select().from(courseEnrollments).where(eq(courseEnrollments.id, enrollId));
      return res.json({ success: true, enrollment });
    } catch (error) {
      console.error("[Razorpay] Verify payment error:", error);
      return res.status(500).json({ success: false, message: "Failed to verify payment" });
    }
  });

  app.get("/api/payments/checkout", (req, res) => {
    const { orderId, amount, keyId, courseName, teacherName, studentName, studentPhone, studentEmail, courseId, studentId } = req.query;

    const domain = process.env.REPLIT_DEV_DOMAIN || process.env.REPLIT_DOMAINS?.split(',')[0] || 'localhost:5000';
    const baseUrl = domain.startsWith('http') ? domain : `https://${domain}`;

    const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Payment - ${courseName || 'Course'}</title>
  <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #0D0D0D; color: #fff; min-height: 100vh;
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      padding: 20px;
    }
    .container { text-align: center; max-width: 400px; width: 100%; }
    .logo { font-size: 28px; font-weight: 800; color: #FF6B35; margin-bottom: 24px; }
    .course-name { font-size: 20px; font-weight: 600; margin-bottom: 8px; }
    .teacher { color: #999; font-size: 14px; margin-bottom: 24px; }
    .amount { font-size: 36px; font-weight: 700; color: #FF6B35; margin-bottom: 32px; }
    .amount span { font-size: 18px; color: #999; }
    .pay-btn {
      background: #FF6B35; color: #fff; border: none; padding: 16px 48px;
      font-size: 18px; font-weight: 700; border-radius: 12px; cursor: pointer;
      width: 100%; transition: opacity 0.2s;
    }
    .pay-btn:hover { opacity: 0.9; }
    .pay-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .status { margin-top: 24px; font-size: 14px; color: #999; }
    .success { color: #4CAF50; font-size: 18px; font-weight: 600; }
    .failed { color: #F44336; font-size: 18px; font-weight: 600; }
    .spinner { width: 40px; height: 40px; border: 4px solid #333; border-top: 4px solid #FF6B35;
      border-radius: 50%; animation: spin 1s linear infinite; margin: 20px auto; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .secure { display: flex; align-items: center; justify-content: center; gap: 6px;
      margin-top: 16px; color: #666; font-size: 12px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">Mobi</div>
    <div class="course-name">${courseName || 'Course'}</div>
    <div class="teacher">by ${teacherName || 'Teacher'}</div>
    <div class="amount">&#8377;${((parseInt(amount as string) || 0) / 100).toLocaleString('en-IN')} <span>INR</span></div>
    <button class="pay-btn" id="payBtn" onclick="startPayment()">Pay Now</button>
    <div class="status" id="status"></div>
    <div class="secure">&#128274; Secured by Razorpay</div>
  </div>
  <script>
    var paymentDone = false;
    function startPayment() {
      document.getElementById('payBtn').disabled = true;
      document.getElementById('status').innerHTML = '<div class="spinner"></div>Opening payment...';
      var options = {
        key: '${keyId}',
        amount: '${amount}',
        currency: 'INR',
        name: 'Mobi',
        description: '${((courseName as string) || '').replace(/'/g, "\\'")}',
        order_id: '${orderId}',
        prefill: {
          name: '${(studentName as string || '').replace(/'/g, "\\'")}',
          contact: '${studentPhone || ''}',
          email: '${studentEmail || ''}',
        },
        theme: { color: '#FF6B35' },
        handler: function(response) {
          paymentDone = true;
          document.getElementById('status').innerHTML = '<div class="spinner"></div>Verifying payment...';
          document.getElementById('payBtn').style.display = 'none';
          fetch('${baseUrl}/api/payments/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              razorpay_order_id: response.razorpay_order_id,
              razorpay_payment_id: response.razorpay_payment_id,
              razorpay_signature: response.razorpay_signature,
              courseId: '${courseId}',
              studentId: '${studentId}',
              studentName: '${(studentName as string || '').replace(/'/g, "\\'")}',
              studentPhone: '${studentPhone || ''}',
            }),
          })
          .then(function(r) { return r.json(); })
          .then(function(data) {
            if (data.success) {
              document.getElementById('status').innerHTML = '<div class="success">Payment Successful!</div><p style="color:#999;margin-top:8px">Enrollment confirmed. Go back to the app.</p>';
              if (window.ReactNativeWebView) {
                window.ReactNativeWebView.postMessage(JSON.stringify({ type: 'payment_success', enrollment: data.enrollment }));
              }
            } else {
              document.getElementById('status').innerHTML = '<div class="failed">Verification Failed</div><p style="color:#999;margin-top:8px">' + (data.message || 'Please contact support') + '</p>';
              if (window.ReactNativeWebView) {
                window.ReactNativeWebView.postMessage(JSON.stringify({ type: 'payment_failed', message: data.message }));
              }
            }
          })
          .catch(function(err) {
            document.getElementById('status').innerHTML = '<div class="failed">Error</div><p style="color:#999;margin-top:8px">Network error. Please try again.</p>';
            if (window.ReactNativeWebView) {
              window.ReactNativeWebView.postMessage(JSON.stringify({ type: 'payment_error', message: err.message }));
            }
          });
        },
        modal: {
          ondismiss: function() {
            if (!paymentDone) {
              document.getElementById('payBtn').disabled = false;
              document.getElementById('status').innerHTML = '<p style="color:#F9A825">Payment cancelled</p>';
              if (window.ReactNativeWebView) {
                window.ReactNativeWebView.postMessage(JSON.stringify({ type: 'payment_cancelled' }));
              }
            }
          }
        }
      };
      var rzp = new Razorpay(options);
      rzp.on('payment.failed', function(response) {
        document.getElementById('payBtn').disabled = false;
        document.getElementById('status').innerHTML = '<div class="failed">Payment Failed</div><p style="color:#999;margin-top:8px">' + (response.error.description || 'Please try again') + '</p>';
        if (window.ReactNativeWebView) {
          window.ReactNativeWebView.postMessage(JSON.stringify({ type: 'payment_failed', message: response.error.description }));
        }
      });
      rzp.open();
    }
    setTimeout(startPayment, 500);
  </script>
</body>
</html>`;
    res.type('html').send(html);
  });

  app.get("/api/payments", async (req, res) => {
    try {
      const { studentId, teacherId, courseId } = req.query;
      let result;
      if (studentId) {
        result = await db.select().from(payments).where(eq(payments.studentId, studentId as string)).orderBy(desc(payments.createdAt));
      } else if (teacherId) {
        result = await db.select().from(payments).where(eq(payments.teacherId, teacherId as string)).orderBy(desc(payments.createdAt));
      } else if (courseId) {
        result = await db.select().from(payments).where(eq(payments.courseId, courseId as string)).orderBy(desc(payments.createdAt));
      } else {
        result = await db.select().from(payments).orderBy(desc(payments.createdAt));
      }
      return res.json(result);
    } catch (error) {
      console.error("[Payments] List error:", error);
      return res.status(500).json({ success: false, message: "Failed to get payments" });
    }
  });

  // ==================== CHAT CONTACT PERMISSION ====================
  app.get("/api/chat/can-contact/:teacherId", async (req, res) => {
    try {
      const { teacherId } = req.params;
      const { studentId } = req.query;
      if (!studentId) {
        return res.status(400).json({ success: false, message: "studentId query param is required" });
      }

      const now = Date.now();
      const activeEnrollments = await db.select().from(courseEnrollments)
        .where(and(
          eq(courseEnrollments.studentId, studentId as string),
          eq(courseEnrollments.teacherId, teacherId),
          gt(courseEnrollments.expiresAt, now)
        ));

      if (activeEnrollments.length > 0) {
        return res.json({ canContact: true, reason: "Active enrollment found" });
      }
      return res.json({ canContact: false, reason: "No active enrollment with this teacher" });
    } catch (error) {
      console.error("[Chat] Can contact check error:", error);
      return res.status(500).json({ success: false, message: "Failed to check contact permission" });
    }
  });

  app.post("/api/dubbing/start", async (req, res) => {
    try {
      const { videoId, courseId, targetLanguage, sourceLang } = req.body;
      if (!videoId || !courseId || !targetLanguage) {
        return res.status(400).json({ success: false, message: "videoId, courseId, and targetLanguage are required" });
      }

      const existingDubbed = await db.select().from(dubbedVideos)
        .where(and(
          eq(dubbedVideos.videoId, videoId),
          eq(dubbedVideos.language, targetLanguage)
        ));

      if (existingDubbed.length > 0) {
        const existing = existingDubbed[0];
        if (existing.status === "completed") {
          return res.json({ success: true, status: "completed", dubbedVideoUrl: existing.dubbedVideoUrl });
        }
        if (existing.status === "processing") {
          return res.json({ success: true, status: "processing", message: "Dubbing already in progress" });
        }
        await db.delete(dubbedVideos).where(eq(dubbedVideos.id, existing.id));
      }

      const { dubVideo } = await import("./dubbing");
      res.json({ success: true, status: "processing", message: "Dubbing started" });

      dubVideo(videoId, courseId, targetLanguage, sourceLang || "hi").then(result => {
        console.log(`[Dubbing] Completed for video ${videoId} to ${targetLanguage}:`, result.success ? "success" : result.error);
      });
    } catch (error) {
      console.error("[Dubbing] Start error:", error);
      return res.status(500).json({ success: false, message: "Failed to start dubbing" });
    }
  });

  app.get("/api/dubbing/status/:videoId", async (req, res) => {
    try {
      const { videoId } = req.params;
      const { language } = req.query;

      let query = db.select().from(dubbedVideos).where(eq(dubbedVideos.videoId, videoId));
      const results = await query;

      if (language) {
        const filtered = results.filter(r => r.language === language);
        if (filtered.length === 0) {
          return res.json({ available: false, status: null });
        }
        return res.json({
          available: filtered[0].status === "completed",
          status: filtered[0].status,
          dubbedVideoUrl: filtered[0].dubbedVideoUrl,
        });
      }

      const langMap: Record<string, { status: string; url: string }> = {};
      for (const d of results) {
        langMap[d.language] = { status: d.status, url: d.dubbedVideoUrl };
      }
      return res.json({ languages: langMap });
    } catch (error) {
      console.error("[Dubbing] Status error:", error);
      return res.status(500).json({ success: false, message: "Failed to get dubbing status" });
    }
  });

  app.get("/api/dubbing/languages", (_req, res) => {
    const languages = [
      { code: "hi", name: "Hindi", nativeName: "हिन्दी" },
      { code: "ta", name: "Tamil", nativeName: "தமிழ்" },
      { code: "te", name: "Telugu", nativeName: "తెలుగు" },
      { code: "kn", name: "Kannada", nativeName: "ಕನ್ನಡ" },
      { code: "ml", name: "Malayalam", nativeName: "മലയാളം" },
      { code: "bn", name: "Bengali", nativeName: "বাংলা" },
      { code: "mr", name: "Marathi", nativeName: "मराठी" },
      { code: "gu", name: "Gujarati", nativeName: "ગુજરાતી" },
      { code: "pa", name: "Punjabi", nativeName: "ਪੰਜਾਬੀ" },
      { code: "or", name: "Odia", nativeName: "ଓଡ଼ିଆ" },
      { code: "ur", name: "Urdu", nativeName: "اردو" },
      { code: "en", name: "English", nativeName: "English" },
    ];
    res.json({ languages });
  });

  // ========== Live Classes routes ==========
  app.get("/api/courses/:courseId/live-classes", async (req, res) => {
    try {
      const { courseId } = req.params;
      const classes = await db.select().from(liveClasses)
        .where(eq(liveClasses.courseId, courseId))
        .orderBy(desc(liveClasses.scheduledAt));
      return res.json(classes);
    } catch (error) {
      console.error("[LiveClasses] List error:", error);
      return res.status(500).json({ success: false, message: "Failed to get live classes" });
    }
  });

  app.post("/api/courses/:courseId/live-classes", async (req, res) => {
    try {
      const { courseId } = req.params;
      const { teacherId, teacherName, title, description, scheduledAt, duration } = req.body;
      const [lc] = await db.insert(liveClasses).values({
        id: randomUUID(),
        courseId,
        teacherId,
        teacherName,
        title,
        description: description || "",
        scheduledAt,
        duration: duration || 60,
        status: "scheduled",
        createdAt: Date.now(),
      }).returning();
      return res.json({ success: true, liveClass: lc });
    } catch (error) {
      console.error("[LiveClasses] Create error:", error);
      return res.status(500).json({ success: false, message: "Failed to create live class" });
    }
  });

  app.patch("/api/live-classes/:id/status", async (req, res) => {
    try {
      const { id } = req.params;
      const { status, meetingUrl } = req.body;
      const updates: any = { status };
      if (meetingUrl) updates.meetingUrl = meetingUrl;
      const [updated] = await db.update(liveClasses).set(updates).where(eq(liveClasses.id, id)).returning();
      return res.json({ success: true, liveClass: updated });
    } catch (error) {
      console.error("[LiveClasses] Update error:", error);
      return res.status(500).json({ success: false, message: "Failed to update live class" });
    }
  });

  app.delete("/api/live-classes/:id", async (req, res) => {
    try {
      await db.delete(liveClasses).where(eq(liveClasses.id, req.params.id));
      return res.json({ success: true });
    } catch (error) {
      console.error("[LiveClasses] Delete error:", error);
      return res.status(500).json({ success: false, message: "Failed to delete live class" });
    }
  });

  // ========== Course Students routes ==========
  app.get("/api/courses/:courseId/students", async (req, res) => {
    try {
      const { courseId } = req.params;
      const enrollments = await db.select().from(courseEnrollments)
        .where(eq(courseEnrollments.courseId, courseId))
        .orderBy(desc(courseEnrollments.createdAt));
      return res.json(enrollments);
    } catch (error) {
      console.error("[Students] List error:", error);
      return res.status(500).json({ success: false, message: "Failed to get students" });
    }
  });

  // ========== Course Notices routes ==========
  app.get("/api/courses/:courseId/notices", async (req, res) => {
    try {
      const { courseId } = req.params;
      const notices = await db.select().from(courseNotices)
        .where(eq(courseNotices.courseId, courseId))
        .orderBy(desc(courseNotices.createdAt));
      return res.json(notices);
    } catch (error) {
      console.error("[Notices] List error:", error);
      return res.status(500).json({ success: false, message: "Failed to get notices" });
    }
  });

  app.post("/api/courses/:courseId/notices", async (req, res) => {
    try {
      const { courseId } = req.params;
      const { teacherId, teacherName, title, message } = req.body;
      const [notice] = await db.insert(courseNotices).values({
        id: randomUUID(),
        courseId,
        teacherId,
        teacherName,
        title,
        message: message || "",
        createdAt: Date.now(),
      }).returning();
      return res.json({ success: true, notice });
    } catch (error) {
      console.error("[Notices] Create error:", error);
      return res.status(500).json({ success: false, message: "Failed to create notice" });
    }
  });

  app.delete("/api/notices/:id", async (req, res) => {
    try {
      await db.delete(courseNotices).where(eq(courseNotices.id, req.params.id));
      return res.json({ success: true });
    } catch (error) {
      console.error("[Notices] Delete error:", error);
      return res.status(500).json({ success: false, message: "Failed to delete notice" });
    }
  });

  async function cleanupOldPosts() {
    try {
      const cutoff = Date.now() - 24 * 60 * 60 * 1000;
      const oldPosts = await db.select().from(posts).where(lt(posts.createdAt, cutoff));

      if (oldPosts.length === 0) return;

      for (const post of oldPosts) {
        try {
          const images: string[] = JSON.parse(post.images);
          for (const imgUrl of images) {
            if (imgUrl.startsWith('/uploads/')) {
              const filePath = path.resolve(process.cwd(), imgUrl.slice(1));
              if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
              }
            }
          }
        } catch (e) { }
      }

      await db.delete(posts).where(lt(posts.createdAt, cutoff));
      console.log(`[Cleanup] Deleted ${oldPosts.length} posts older than 24 hours`);
    } catch (error) {
      console.error("[Cleanup] Error cleaning old posts:", error);
    }
  }

  cleanupOldPosts();
  setInterval(cleanupOldPosts, 60 * 60 * 1000);

  app.get("/api/ads", async (_req, res) => {
    try {
      const allAds = await db.select().from(ads).orderBy(ads.sortOrder);
      res.json(allAds);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch ads" });
    }
  });

  app.get("/api/ads/active", async (_req, res) => {
    try {
      const activeAds = await db.select().from(ads).where(eq(ads.isActive, 1)).orderBy(ads.sortOrder);
      res.json(activeAds);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch active ads" });
    }
  });

  app.post("/api/ads", upload.single("image"), async (req, res) => {
    try {
      const { title, description, videoUrl, linkUrl, sortOrder } = req.body;
      let imageUrl = req.body.imageUrl || "";
      if (req.file) {
        const ext = path.extname(req.file.originalname);
        const filename = `images/ad-${randomUUID()}${ext}`;
        imageUrl = await uploadToStorage(req.file.buffer, filename);
      }
      const [ad] = await db.insert(ads).values({
        id: randomUUID(),
        title: title || "",
        description: description || "",
        imageUrl,
        videoUrl: videoUrl || "",
        linkUrl: linkUrl || "",
        sortOrder: parseInt(sortOrder) || 0,
        createdAt: Date.now(),
      }).returning();
      res.json(ad);
    } catch (error) {
      console.error("Error creating ad:", error);
      res.status(500).json({ error: "Failed to create ad" });
    }
  });

  app.patch("/api/ads/:id", upload.single("image"), async (req, res) => {
    try {
      const { id } = req.params;
      const updates: any = {};
      if (req.body.title !== undefined) updates.title = req.body.title;
      if (req.body.description !== undefined) updates.description = req.body.description;
      if (req.body.videoUrl !== undefined) updates.videoUrl = req.body.videoUrl;
      if (req.body.linkUrl !== undefined) updates.linkUrl = req.body.linkUrl;
      if (req.body.isActive !== undefined) updates.isActive = parseInt(req.body.isActive);
      if (req.body.sortOrder !== undefined) updates.sortOrder = parseInt(req.body.sortOrder);
      if (req.file) {
        const ext = path.extname(req.file.originalname);
        const filename = `images/ad-${randomUUID()}${ext}`;
        updates.imageUrl = await uploadToStorage(req.file.buffer, filename);
      } else if (req.body.imageUrl !== undefined) {
        updates.imageUrl = req.body.imageUrl;
      }
      const [updated] = await db.update(ads).set(updates).where(eq(ads.id, id as string)).returning();
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: "Failed to update ad" });
    }
  });

  app.delete("/api/ads/:id", async (req, res) => {
    try {
      await db.delete(ads).where(eq(ads.id, req.params.id as string));
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete ad" });
    }
  });

  app.get("/api/live-chat/messages", async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 50;
      const before = req.query.before ? parseInt(req.query.before as string) : undefined;
      let msgs;
      if (before) {
        msgs = await db.select().from(liveChatMessages).where(lt(liveChatMessages.createdAt, before)).orderBy(desc(liveChatMessages.createdAt)).limit(limit);
      } else {
        msgs = await db.select().from(liveChatMessages).orderBy(desc(liveChatMessages.createdAt)).limit(limit);
      }
      res.json(msgs.reverse());
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch live chat messages" });
    }
  });

  app.post("/api/live-chat/messages", async (req, res) => {
    try {
      const { senderId, senderName, senderRole, senderAvatar, message, image } = req.body;
      if (!senderId || (!message && !image)) {
        return res.status(400).json({ error: "senderId and message or image required" });
      }
      const [msg] = await db.insert(liveChatMessages).values({
        id: randomUUID(),
        senderId,
        senderName: senderName || "",
        senderRole: senderRole || "",
        senderAvatar: senderAvatar || "",
        message: message || "",
        image: image || "",
        createdAt: Date.now(),
      }).returning();
      res.json(msg);
    } catch (error) {
      res.status(500).json({ error: "Failed to send message" });
    }
  });

  app.get('/api/app-settings', async (_req, res) => {
    try {
      const settings = await db.select().from(appSettings);
      const result: Record<string, string> = {};
      settings.forEach(s => { result[s.key] = s.value; });
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch settings' });
    }
  });

  app.get('/api/app-settings/:key', async (req, res) => {
    try {
      const [setting] = await db.select().from(appSettings).where(eq(appSettings.key, req.params.key));
      res.json({ value: setting?.value || '' });
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch setting' });
    }
  });

  app.put('/api/app-settings/:key', async (req, res) => {
    try {
      const { value } = req.body;
      const key = req.params.key;
      const [existing] = await db.select().from(appSettings).where(eq(appSettings.key, key));
      if (existing) {
        await db.update(appSettings).set({ value: value || '', updatedAt: Date.now() }).where(eq(appSettings.key, key));
      } else {
        await db.insert(appSettings).values({ key, value: value || '', updatedAt: Date.now() });
      }
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: 'Failed to update setting' });
    }
  });

  const httpServer = createServer(app);

  const { Server: SocketIOServer } = await import("socket.io");
  const io = new SocketIOServer(httpServer, {
    cors: { origin: "*", methods: ["GET", "POST"] },
    path: "/socket.io",
  });

  const onlineUsers = new Map<string, { name: string; role: string; socketId: string }>();

  io.on("connection", (socket) => {
    console.log("[Socket.IO] User connected:", socket.id);

    socket.on("join_live_chat", (userData: { userId: string; name: string; role: string }) => {
      if (userData.userId) {
        const wasAlreadyOnline = onlineUsers.has(userData.userId);
        onlineUsers.set(userData.userId, { name: userData.name, role: userData.role, socketId: socket.id });
        io.emit("online_users", Array.from(onlineUsers.entries()).map(([id, u]) => ({ id, name: u.name, role: u.role })));
        if (!wasAlreadyOnline) {
          io.to("live_chat_room").emit("user_joined", { name: userData.name, role: userData.role });
        }
      }
      socket.join("live_chat_room");
    });

    socket.on("send_live_message", async (data: { senderId: string; senderName: string; senderRole: string; senderAvatar: string; message: string; image?: string; video?: string }) => {
      try {
        const [msg] = await db.insert(liveChatMessages).values({
          id: randomUUID(),
          senderId: data.senderId,
          senderName: data.senderName || "",
          senderRole: data.senderRole || "",
          senderAvatar: data.senderAvatar || "",
          message: data.message || "",
          image: data.image || "",
          video: data.video || "",
          createdAt: Date.now(),
        }).returning();
        io.to("live_chat_room").emit("new_live_message", msg);
      } catch (err) {
        console.error("[Socket.IO] Error saving message:", err);
      }
    });

    socket.on("delete_live_message", async (data: { messageId: string; phone: string }) => {
      if (data.phone !== '8179142535') return;
      try {
        await db.delete(liveChatMessages).where(eq(liveChatMessages.id, data.messageId));
        io.to("live_chat_room").emit("live_message_deleted", { messageId: data.messageId });
      } catch (err) {
        console.error("[Socket.IO] Error deleting message:", err);
      }
    });

    socket.on("typing_live", (data: { name: string }) => {
      socket.to("live_chat_room").emit("user_typing", { name: data.name });
    });

    socket.on("disconnect", () => {
      for (const [userId, userData] of onlineUsers) {
        if (userData.socketId === socket.id) {
          onlineUsers.delete(userId);
          break;
        }
      }
      io.emit("online_users", Array.from(onlineUsers.entries()).map(([id, u]) => ({ id, name: u.name, role: u.role })));
      console.log("[Socket.IO] User disconnected:", socket.id);
    });
  });

  return httpServer;
}
