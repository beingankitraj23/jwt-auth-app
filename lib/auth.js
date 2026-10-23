const jwt = require('jsonwebtoken');

const ISSUER = 'jwt-auth-app';
const AUDIENCE = 'jwt-auth-app-users';
const EXPIRES_IN_SECONDS = 60 * 60; // 1 hour
const COOKIE_NAME = 'token';

const isProd = process.env.NODE_ENV === 'production' || !!process.env.VERCEL;

function signToken(user) {
  return jwt.sign({ email: user.email, name: user.name }, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    subject: String(user.id),
    issuer: ISSUER,
    audience: AUDIENCE,
    expiresIn: EXPIRES_IN_SECONDS,
  });
}

function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true, // not readable by JavaScript -> mitigates XSS token theft
    secure: isProd, // HTTPS only in production
    sameSite: 'strict', // not sent on cross-site requests -> mitigates CSRF
    maxAge: EXPIRES_IN_SECONDS * 1000,
    path: '/',
  });
}

function clearAuthCookie(res) {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: isProd, sameSite: 'strict', path: '/' });
}

function extractToken(req) {
  const header = req.headers.authorization || '';
  if (header.startsWith('Bearer ')) return header.slice(7).trim();
  return req.cookies && req.cookies[COOKIE_NAME] ? req.cookies[COOKIE_NAME] : null;
}

// Protected-route middleware: verifies signature, expiry, issuer and audience.
function requireAuth(req, res, next) {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });

  try {
    const claims = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'], // pin the algorithm (blocks "alg: none" / algorithm confusion)
      issuer: ISSUER,
      audience: AUDIENCE,
    });
    req.user = { id: claims.sub, email: claims.email, name: claims.name, exp: claims.exp };
    return next();
  } catch (err) {
    const expired = err.name === 'TokenExpiredError';
    return res.status(401).json({
      error: expired ? 'Session expired, please log in again' : 'Invalid token',
      code: expired ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID',
    });
  }
}

module.exports = { signToken, setAuthCookie, clearAuthCookie, requireAuth, EXPIRES_IN_SECONDS };
