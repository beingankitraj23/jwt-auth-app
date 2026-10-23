require('dotenv').config(); // loads .env if present (ignored on Vercel, which injects its own env vars)
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const path = require('path');

const db = require('../lib/db');
const { signToken, setAuthCookie, clearAuthCookie, requireAuth, EXPIRES_IN_SECONDS } = require('../lib/auth');

const app = express();
const isProd = process.env.NODE_ENV === 'production' || !!process.env.VERCEL;

// Local dev convenience: no JWT_SECRET? Use a temporary random one (sessions reset on restart).
// In production (Vercel) a real JWT_SECRET is still required.
if (!process.env.JWT_SECRET && !isProd) {
  process.env.JWT_SECRET = require('crypto').randomBytes(48).toString('hex');
  console.warn('JWT_SECRET not set: using a temporary random secret for local development.');
}

const BCRYPT_ROUNDS = 12;
// Used to keep login timing similar whether or not the email exists.
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', BCRYPT_ROUNDS);

app.set('trust proxy', 1); // Vercel sits behind a proxy (needed for correct client IPs)
app.use(helmet());
app.use(express.json({ limit: '10kb' })); // JSON only: cross-site form posts can't reach these routes
app.use(cookieParser());

// Fail cleanly (not with a crash) if the deployment is misconfigured.
app.use((req, res, next) => {
  const secret = process.env.JWT_SECRET;
  if (!secret || (isProd && secret.length < 32)) {
    console.error('JWT_SECRET is missing or shorter than 32 characters');
    return res.status(500).json({ error: 'Server misconfigured' });
  }
  if (isProd && db.useMemory) {
    console.error('DATABASE_URL is not set');
    return res.status(500).json({ error: 'Server misconfigured' });
  }
  next();
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, try again in a few minutes' },
});

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function validateCredentials({ name, email, password }, { requireName }) {
  const errors = [];
  if (requireName && (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 80)) {
    errors.push('Name must be 2–80 characters');
  }
  if (typeof email !== 'string' || email.length > 254 || !EMAIL_RE.test(email.trim())) {
    errors.push('Enter a valid email address');
  }
  if (typeof password !== 'string') {
    errors.push('Password is required');
  } else if (requireName) {
    // bcrypt only uses the first 72 bytes, so cap there
    if (password.length < 8 || Buffer.byteLength(password) > 72 || !/[A-Za-z]/.test(password) || !/\d/.test(password)) {
      errors.push('Password must be 8–72 characters and include a letter and a number');
    }
  } else if (password.length === 0 || Buffer.byteLength(password) > 72) {
    errors.push('Password is required');
  }
  return errors;
}

const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email });

// ---------- Auth routes ----------
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    const errors = validateCredentials(body, { requireName: true });
    if (errors.length) return res.status(400).json({ error: errors[0], errors });

    const email = body.email.trim().toLowerCase();
    const passwordHash = await bcrypt.hash(body.password, BCRYPT_ROUNDS); // salted automatically

    let user;
    try {
      user = await db.createUser({ name: body.name.trim(), email, passwordHash });
    } catch (err) {
      if (err.code === '23505') return res.status(409).json({ error: 'An account with this email already exists' });
      throw err;
    }

    const token = signToken(user);
    setAuthCookie(res, token);
    return res.status(201).json({ user: publicUser(user), token, expiresIn: EXPIRES_IN_SECONDS });
  } catch (err) {
    console.error('register error:', err);
    return res.status(500).json({ error: 'Something went wrong' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    const errors = validateCredentials(body, { requireName: false });
    if (errors.length) return res.status(400).json({ error: 'Email and password are required' });

    const email = body.email.trim().toLowerCase();
    const user = await db.findByEmail(email);
    const ok = await bcrypt.compare(body.password, user ? user.password_hash : DUMMY_HASH);

    if (!user || !ok) return res.status(401).json({ error: 'Invalid email or password' });

    const token = signToken(user);
    setAuthCookie(res, token);
    return res.json({ user: publicUser(user), token, expiresIn: EXPIRES_IN_SECONDS });
  } catch (err) {
    console.error('login error:', err);
    return res.status(500).json({ error: 'Something went wrong' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  clearAuthCookie(res);
  res.json({ message: 'Logged out' });
});

// ---------- Protected routes ----------
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const user = await db.findById(req.user.id);
    if (!user) {
      clearAuthCookie(res);
      return res.status(401).json({ error: 'Account no longer exists', code: 'TOKEN_INVALID' });
    }
    res.json({ user: publicUser(user), tokenExpiresAt: new Date(req.user.exp * 1000).toISOString() });
  } catch (err) {
    console.error('me error:', err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.get('/api/protected/dashboard', requireAuth, (req, res) => {
  res.json({
    message: `Hello ${req.user.name}, this data is only visible to authenticated users.`,
    servedAt: new Date().toISOString(),
    claims: { sub: req.user.id, email: req.user.email },
  });
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

// Local dev only: Vercel serves /public itself.
if (!process.env.VERCEL) {
  app.use(express.static(path.join(__dirname, '..', 'public')));
}

if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`http://localhost:${port}`));
}

module.exports = app;
