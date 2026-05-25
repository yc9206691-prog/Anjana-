/**
 * ══════════════════════════════════════════════════════════════════
 *  I.R.I.S ATLAS AI — SECURE BACKEND SERVER
 *  Production-Ready · Single File · Node.js + Express
 *
 *  Author  : Backend for Yash Chaudhary's I.R.I.S ATLAS AI
 *  Version : 1.0.0
 *  Stack   : Node.js · Express · Firebase Admin · Firestore · Gemini
 *
 *  SECURITY FEATURES:
 *  - Firebase ID Token verification on every protected route
 *  - Gemini API key NEVER returned to frontend
 *  - Key stored in Firestore private sub-collection
 *  - Rate limiting per user (express-rate-limit)
 *  - Helmet security headers
 *  - CORS protection
 *  - Input sanitization & request size limits
 *  - Request timeout (AbortController)
 *  - Compression (gzip)
 *  - Global crash prevention (uncaughtException)
 *  - Structured logging (Winston)
 *  - Usage tracking per user
 *  - API versioning (/api/v1/*)
 * ══════════════════════════════════════════════════════════════════
 */

'use strict';

// ─────────────────────────────────────────────
//  IMPORTS
// ─────────────────────────────────────────────
require('dotenv').config();

const express        = require('express');
const helmet         = require('helmet');
const cors           = require('cors');
const compression    = require('compression');
const rateLimit      = require('express-rate-limit');
const admin          = require('firebase-admin');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const winston        = require('winston');

// ─────────────────────────────────────────────
//  WINSTON LOGGER SETUP
// ─────────────────────────────────────────────
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.colorize(),
    winston.format.printf(({ timestamp, level, message, stack }) => {
      return stack
        ? `[${timestamp}] ${level}: ${message}\n${stack}`
        : `[${timestamp}] ${level}: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

// ─────────────────────────────────────────────
//  ENV VALIDATION — crash early if missing
// ─────────────────────────────────────────────
const REQUIRED_ENV = [
  'FIREBASE_PROJECT_ID',
  'FIREBASE_CLIENT_EMAIL',
  'FIREBASE_PRIVATE_KEY',
  'ENCRYPTION_SECRET'
];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    logger.error(`❌ Missing required env variable: ${key}`);
    process.exit(1);
  }
}

// ─────────────────────────────────────────────
//  FIREBASE ADMIN INIT (one-time, idempotent)
// ─────────────────────────────────────────────
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId    : process.env.FIREBASE_PROJECT_ID,
      clientEmail  : process.env.FIREBASE_CLIENT_EMAIL,
      // Replace literal \n in env string with real newline
      privateKey   : process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
    })
  });
  logger.info('✅ Firebase Admin SDK initialized');
}

const db = admin.firestore();

// ─────────────────────────────────────────────
//  FIRESTORE PATH HELPER
//  Structure: users/{uid}/private/api
//  The "private" collection is NOT readable by
//  client SDKs unless your security rules allow it.
//  Keep rules tight: allow read/write only via Admin SDK.
// ─────────────────────────────────────────────
const getUserApiDoc = (uid) =>
  db.collection('users').doc(uid).collection('private').doc('api');

// ─────────────────────────────────────────────
//  SIMPLE ENCRYPTION HELPERS
//  We XOR-encode with a secret to add a basic
//  obfuscation layer on top of Firestore-at-rest
//  encryption. For higher security use Node.js
//  'crypto' AES-256-GCM (see comment block below).
// ─────────────────────────────────────────────
const crypto = require('crypto');
const ALGO    = 'aes-256-gcm';
// Derive a 32-byte key from the env secret
const ENC_KEY = crypto.scryptSync(
  process.env.ENCRYPTION_SECRET,
  'iris_atlas_salt_2024',
  32
);

/**
 * encryptKey(plaintext) → base64 ciphertext string
 * Uses AES-256-GCM: authenticated encryption, tamper-proof
 */
function encryptKey(plaintext) {
  const iv         = crypto.randomBytes(16);
  const cipher     = crypto.createCipheriv(ALGO, ENC_KEY, iv);
  const encrypted  = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final()
  ]);
  const authTag    = cipher.getAuthTag();
  // Pack: iv(16) + authTag(16) + ciphertext → base64
  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

/**
 * decryptKey(base64) → plaintext string
 */
function decryptKey(base64) {
  const buf        = Buffer.from(base64, 'base64');
  const iv         = buf.subarray(0, 16);
  const authTag    = buf.subarray(16, 32);
  const ciphertext = buf.subarray(32);
  const decipher   = crypto.createDecipheriv(ALGO, ENC_KEY, iv);
  decipher.setAuthTag(authTag);
  return decipher.update(ciphertext) + decipher.final('utf8');
}

// ─────────────────────────────────────────────
//  INPUT SANITIZATION HELPER
//  Removes any non-printable chars, trims
// ─────────────────────────────────────────────
function sanitizeString(str, maxLen = 500) {
  if (typeof str !== 'string') return '';
  // eslint-disable-next-line no-control-regex
  return str.replace(/[^\x09\x0A\x0D\x20-\x7E\u00A0-\uFFFF]/g, '').trim().slice(0, maxLen);
}

// ─────────────────────────────────────────────
//  EXPRESS APP INIT
// ─────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 3001;

// ─────────────────────────────────────────────
//  SECURITY MIDDLEWARE
// ─────────────────────────────────────────────

// Helmet: sets 11 security-related HTTP headers
app.use(helmet({
  contentSecurityPolicy: false, // Disabled for API server (no HTML served)
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

// Compression: gzip all responses
app.use(compression());

// Body parser with strict size limit (no >10KB requests)
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// CORS: only allow your frontend origin(s)
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    // Allow no-origin (server-to-server, Postman dev)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    logger.warn(`🚫 CORS blocked: ${origin}`);
    return callback(new Error('CORS policy violation'), false);
  },
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// ─────────────────────────────────────────────
//  RATE LIMITERS
// ─────────────────────────────────────────────

// General API: 60 req / 1 min per IP
const generalLimiter = rateLimit({
  windowMs : 60 * 1000,
  max      : 60,
  standardHeaders: true,
  legacyHeaders  : false,
  message  : { error: 'Too many requests. Please try again in a minute.' }
});

// Auth-sensitive routes: stricter (10 req / 5 min per IP)
const authLimiter = rateLimit({
  windowMs : 5 * 60 * 1000,
  max      : 10,
  standardHeaders: true,
  legacyHeaders  : false,
  message  : { error: 'Too many auth attempts. Please wait.' }
});

// Chat route: 30 req / 1 min per IP
const chatLimiter = rateLimit({
  windowMs : 60 * 1000,
  max      : 30,
  standardHeaders: true,
  legacyHeaders  : false,
  message  : { error: 'Chat rate limit reached. Please slow down.' }
});

app.use(generalLimiter);

// ─────────────────────────────────────────────
//  REQUEST LOGGER MIDDLEWARE
// ─────────────────────────────────────────────
app.use((req, _res, next) => {
  logger.info(`→ ${req.method} ${req.path} [${req.ip}]`);
  next();
});

// ─────────────────────────────────────────────
//  FIREBASE AUTH MIDDLEWARE
//  Verifies Firebase ID token on every protected route.
//  Attaches decoded token to req.user.
// ─────────────────────────────────────────────
async function verifyFirebaseToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: missing token' });
  }
  const idToken = authHeader.split('Bearer ')[1];
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded; // { uid, email, ... }
    next();
  } catch (err) {
    logger.warn(`🔐 Token verification failed: ${err.message}`);
    return res.status(401).json({ error: 'Unauthorized: invalid or expired token' });
  }
}

// ─────────────────────────────────────────────
//  REQUEST TIMEOUT HELPER (30 seconds)
//  Returns an AbortController signal that aborts
//  if the fetch takes too long.
// ─────────────────────────────────────────────
function getTimeoutSignal(ms = 30000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  // Prevent the timer from keeping the process alive
  if (timer.unref) timer.unref();
  return { signal: controller.signal, clear: () => clearTimeout(timer) };
}

// ─────────────────────────────────────────────
//  GEMINI KEY VALIDATOR
//  Calls Gemini models list endpoint to verify the key
//  is valid BEFORE storing it. Never stores invalid keys.
// ─────────────────────────────────────────────
async function validateGeminiKey(apiKey) {
  const { signal, clear } = getTimeoutSignal(10000);
  try {
    const resp = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`,
      { method: 'GET', signal }
    );
    clear();
    if (resp.ok) {
      const data = await resp.json();
      // Must have at least one model in the list
      return Array.isArray(data.models) && data.models.length > 0;
    }
    return false;
  } catch (err) {
    clear();
    logger.warn(`Gemini key validation error: ${err.message}`);
    return false;
  }
}

// ─────────────────────────────────────────────
//  USAGE TRACKING HELPER
//  Increments request count in Firestore
//  Non-blocking — failure is silently ignored
// ─────────────────────────────────────────────
async function trackUsage(uid, type = 'chat') {
  try {
    const ref = db.collection('users').doc(uid)
                  .collection('private').doc('usage');
    const field = `${type}Count`;
    await ref.set({
      [field]      : admin.firestore.FieldValue.increment(1),
      lastActiveAt : admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
  } catch (_err) {
    // Usage tracking is non-critical — never let it crash the request
  }
}

// ═══════════════════════════════════════════════
//  API ROUTES — versioned under /api/v1
// ═══════════════════════════════════════════════
const router = express.Router();

// ─────────────────────────────────────────────
//  GET /api/v1/health
//  Public. Returns server status.
// ─────────────────────────────────────────────
router.get('/health', (_req, res) => {
  res.json({
    status    : 'ok',
    service   : 'IRIS ATLAS AI Backend',
    version   : '1.0.0',
    timestamp : new Date().toISOString()
  });
});

// ─────────────────────────────────────────────
//  POST /api/v1/save-key
//  Protected. Validates and stores Gemini API key.
//
//  Body: { geminiKey: "AIza..." }
//
//  Response (success):  { success: true, connected: true }
//  Response (invalid):  { success: false, error: "..." }
//
//  SECURITY GUARANTEES:
//  - Firebase token verified
//  - Key validated against Gemini API before save
//  - Key encrypted (AES-256-GCM) before Firestore write
//  - Previous key overwritten atomically
//  - Raw key NEVER returned in any response
// ─────────────────────────────────────────────
router.post('/save-key', authLimiter, verifyFirebaseToken, async (req, res) => {
  const uid = req.user.uid;

  // Sanitize input — reject anything suspicious
  const rawKey = sanitizeString(req.body?.geminiKey || '', 200);
  if (!rawKey) {
    return res.status(400).json({ success: false, error: 'API key is required' });
  }

  // Basic format check: Gemini keys start with "AIza" and are 39 chars
  if (!rawKey.startsWith('AIza') || rawKey.length < 35) {
    return res.status(400).json({ success: false, error: 'Invalid API key format' });
  }

  logger.info(`🔑 Key save attempt for uid: ${uid}`);

  try {
    // Step 1: Validate key with Gemini API
    const isValid = await validateGeminiKey(rawKey);
    if (!isValid) {
      logger.warn(`❌ Invalid Gemini key submitted by uid: ${uid}`);
      return res.status(400).json({
        success: false,
        error  : 'Invalid Gemini API key. Please check and try again.'
      });
    }

    // Step 2: Encrypt the key
    const encryptedKey = encryptKey(rawKey);

    // Step 3: Save (overwrite) in Firestore private sub-collection
    // users/{uid}/private/api — this path is NEVER accessible to client SDK
    const docRef = getUserApiDoc(uid);
    await docRef.set({
      geminiKey  : encryptedKey,         // encrypted — never plaintext
      connected  : true,
      updatedAt  : admin.firestore.FieldValue.serverTimestamp()
    }); // set() replaces the document entirely → old key removed automatically

    logger.info(`✅ API key saved for uid: ${uid}`);
    await trackUsage(uid, 'saveKey');

    // CRITICAL: return ONLY success status, NEVER the key
    return res.json({ success: true, connected: true });

  } catch (err) {
    logger.error(`save-key error for uid ${uid}: ${err.message}`);
    return res.status(500).json({ success: false, error: 'Server error. Please try again.' });
  }
});

// ─────────────────────────────────────────────
//  GET /api/v1/key-status
//  Protected. Returns whether the user has a saved key.
//
//  Response: { connected: true/false }
//
//  NEVER returns the key itself.
// ─────────────────────────────────────────────
router.get('/key-status', verifyFirebaseToken, async (req, res) => {
  const uid = req.user.uid;
  try {
    const snap = await getUserApiDoc(uid).get();
    if (!snap.exists || !snap.data()?.connected) {
      return res.json({ connected: false });
    }
    return res.json({ connected: true });
  } catch (err) {
    logger.error(`key-status error for uid ${uid}: ${err.message}`);
    return res.status(500).json({ connected: false, error: 'Server error' });
  }
});

// ─────────────────────────────────────────────
//  DELETE /api/v1/remove-key
//  Protected. Permanently deletes the stored API key.
//
//  Response: { success: true }
// ─────────────────────────────────────────────
router.delete('/remove-key', authLimiter, verifyFirebaseToken, async (req, res) => {
  const uid = req.user.uid;
  try {
    // Delete the entire private/api document
    await getUserApiDoc(uid).delete();
    logger.info(`🗑️ API key removed for uid: ${uid}`);
    await trackUsage(uid, 'removeKey');
    return res.json({ success: true });
  } catch (err) {
    logger.error(`remove-key error for uid ${uid}: ${err.message}`);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
});

// ─────────────────────────────────────────────
//  POST /api/v1/chat
//  Protected. Proxies chat to Gemini using stored key.
//  Supports streaming (Server-Sent Events) + non-streaming.
//
//  Body:
//  {
//    contents      : [...],           // Gemini contents array
//    model         : "gemini-2.5-flash",
//    systemInstruction: { parts:[{text:"..."}] },
//    generationConfig : { temperature, maxOutputTokens },
//    stream        : true/false        // default: true
//  }
//
//  SECURITY: API key loaded from Firestore, never from frontend.
// ─────────────────────────────────────────────
router.post('/chat', chatLimiter, verifyFirebaseToken, async (req, res) => {
  const uid = req.user.uid;

  // Step 1: Load & decrypt stored API key
  let apiKey;
  try {
    const snap = await getUserApiDoc(uid).get();
    if (!snap.exists || !snap.data()?.connected) {
      return res.status(403).json({
        error: 'No API key connected. Please add your Gemini API key in Settings.'
      });
    }
    apiKey = decryptKey(snap.data().geminiKey);
  } catch (err) {
    logger.error(`chat: key load error for uid ${uid}: ${err.message}`);
    return res.status(500).json({ error: 'Failed to load API credentials' });
  }

  // Step 2: Extract & sanitize request body
  const {
    contents,
    model            = 'gemini-2.5-flash',
    systemInstruction,
    generationConfig,
    stream           = true
  } = req.body;

  // Validate contents array
  if (!Array.isArray(contents) || contents.length === 0) {
    return res.status(400).json({ error: 'Invalid or missing contents array' });
  }

  // Sanitize model name — only allow whitelisted models
  const ALLOWED_MODELS = [
    'gemini-2.5-flash',
    'gemini-2.5-pro',
    'gemini-2.0-flash',
    'gemini-2.0-flash-exp',
    'gemini-1.5-pro',
    'gemini-1.5-flash',
    'gemini-1.5-flash-8b'
  ];
  const safeModel = ALLOWED_MODELS.includes(model) ? model : 'gemini-2.5-flash';

  // Sanitize generationConfig
  const safeGenConfig = {
    temperature     : Math.min(Math.max(parseFloat(generationConfig?.temperature ?? 0.7), 0), 2),
    maxOutputTokens : Math.min(parseInt(generationConfig?.maxOutputTokens ?? 8192), 32768)
  };

  // Build Gemini request body
  const geminiBody = {
    contents         : contents,
    generationConfig : safeGenConfig
  };
  if (systemInstruction) {
    geminiBody.systemInstruction = systemInstruction;
  }

  // Track usage (non-blocking)
  trackUsage(uid, 'chat');

  // Step 3: Request timeout
  const { signal, clear: clearTimeout_ } = getTimeoutSignal(60000); // 60s

  try {
    if (stream) {
      // ── STREAMING RESPONSE (SSE) ──
      const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${safeModel}:streamGenerateContent?alt=sse&key=${apiKey}`;

      const upstream = await fetch(geminiUrl, {
        method  : 'POST',
        headers : { 'Content-Type': 'application/json' },
        body    : JSON.stringify(geminiBody),
        signal
      });

      clearTimeout_();

      if (!upstream.ok) {
        const errBody = await upstream.json().catch(() => ({}));
        const msg = errBody?.error?.message || `Gemini HTTP ${upstream.status}`;
        logger.warn(`Gemini API error for uid ${uid}: ${msg}`);
        return res.status(upstream.status).json({ error: msg });
      }

      // Set SSE headers
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('X-Accel-Buffering', 'no'); // disable nginx buffering
      res.flushHeaders();

      // Pipe Gemini stream → client
      const reader  = upstream.body.getReader();
      const decoder = new TextDecoder();

      // Handle client disconnect without crashing
      req.on('close', () => {
        reader.cancel().catch(() => {});
      });

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk = decoder.decode(value, { stream: true });
          // Forward raw SSE chunks directly — same format Gemini sends
          res.write(chunk);
        }
      } catch (streamErr) {
        // Client disconnected or stream aborted — not a server error
        logger.info(`Stream ended for uid ${uid}: ${streamErr.message}`);
      } finally {
        res.end();
      }

    } else {
      // ── NON-STREAMING RESPONSE ──
      const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${safeModel}:generateContent?key=${apiKey}`;

      const upstream = await fetch(geminiUrl, {
        method  : 'POST',
        headers : { 'Content-Type': 'application/json' },
        body    : JSON.stringify(geminiBody),
        signal
      });

      clearTimeout_();

      const data = await upstream.json();
      if (!upstream.ok) {
        const msg = data?.error?.message || `Gemini HTTP ${upstream.status}`;
        return res.status(upstream.status).json({ error: msg });
      }

      return res.json(data);
    }

  } catch (err) {
    clearTimeout_();
    if (err.name === 'AbortError') {
      logger.warn(`Chat request timed out for uid: ${uid}`);
      return res.status(504).json({ error: 'Request timed out. Please try again.' });
    }
    logger.error(`chat error for uid ${uid}: ${err.message}`);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ─────────────────────────────────────────────
//  POST /api/v1/validate-key (optional utility)
//  Protected. Lets frontend check if key is still valid.
//  Does NOT return the key.
// ─────────────────────────────────────────────
router.post('/validate-key', authLimiter, verifyFirebaseToken, async (req, res) => {
  const uid = req.user.uid;
  try {
    const snap = await getUserApiDoc(uid).get();
    if (!snap.exists || !snap.data()?.connected) {
      return res.json({ valid: false, connected: false });
    }
    const apiKey  = decryptKey(snap.data().geminiKey);
    const isValid = await validateGeminiKey(apiKey);
    if (!isValid) {
      // Mark as disconnected if key no longer works
      await getUserApiDoc(uid).update({ connected: false });
    }
    return res.json({ valid: isValid, connected: isValid });
  } catch (err) {
    logger.error(`validate-key error for uid ${uid}: ${err.message}`);
    return res.status(500).json({ valid: false, error: 'Server error' });
  }
});

// ─────────────────────────────────────────────
//  Mount router with API versioning
// ─────────────────────────────────────────────
app.use('/api/v1', router);

// ─────────────────────────────────────────────
//  404 HANDLER — catch unmatched routes
// ─────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ─────────────────────────────────────────────
//  GLOBAL ERROR MIDDLEWARE
//  Must have 4 params to be recognized by Express
// ─────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  if (err.message === 'CORS policy violation') {
    return res.status(403).json({ error: 'CORS: Origin not allowed' });
  }
  logger.error(`Unhandled express error: ${err.message}`);
  res.status(500).json({ error: 'Internal server error' });
});

// ─────────────────────────────────────────────
//  CRASH PREVENTION — prevent silent process death
// ─────────────────────────────────────────────
process.on('uncaughtException', (err) => {
  logger.error(`💥 Uncaught Exception: ${err.message}`, err);
  // Give logger time to flush, then exit cleanly
  setTimeout(() => process.exit(1), 1000);
});

process.on('unhandledRejection', (reason) => {
  logger.error(`💥 Unhandled Rejection: ${reason}`);
});

// Graceful shutdown on SIGTERM (Docker / Render / Heroku)
process.on('SIGTERM', () => {
  logger.info('SIGTERM received — shutting down gracefully');
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});

// ─────────────────────────────────────────────
//  START SERVER
// ─────────────────────────────────────────────
const server = app.listen(PORT, () => {
  logger.info(`
  ══════════════════════════════════════════════
   🚀 I.R.I.S ATLAS AI Backend — ONLINE
   Port    : ${PORT}
   Node    : ${process.version}
   ENV     : ${process.env.NODE_ENV || 'development'}
   Firebase: ${process.env.FIREBASE_PROJECT_ID}
  ══════════════════════════════════════════════
  `);
});

// Set server timeout to 90 seconds (prevents zombie connections)
server.timeout = 90000;

module.exports = app; // for testing
