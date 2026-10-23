const { Pool } = require('pg');

const useMemory = !process.env.DATABASE_URL;
const mem = { users: [], seq: 1 }; // local-dev fallback only (not persistent)

let pool;
let ready;

function getPool() {
  if (!pool) {
    // max: 1 keeps serverless instances from exhausting DB connections
    pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 1, idleTimeoutMillis: 10000 });
  }
  return pool;
}

function init() {
  if (useMemory) return Promise.resolve();
  if (!ready) {
    ready = getPool()
      .query(
        `CREATE TABLE IF NOT EXISTS users (
           id SERIAL PRIMARY KEY,
           name VARCHAR(80) NOT NULL,
           email VARCHAR(254) NOT NULL UNIQUE,
           password_hash TEXT NOT NULL,
           created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
         )`
      )
      .catch((err) => {
        ready = null; // retry on next request
        throw err;
      });
  }
  return ready;
}

async function createUser({ name, email, passwordHash }) {
  await init();
  if (useMemory) {
    if (mem.users.some((u) => u.email === email)) {
      const err = new Error('duplicate');
      err.code = '23505';
      throw err;
    }
    const user = { id: mem.seq++, name, email, password_hash: passwordHash, created_at: new Date() };
    mem.users.push(user);
    return { id: user.id, name, email, created_at: user.created_at };
  }
  const { rows } = await getPool().query(
    'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email, created_at',
    [name, email, passwordHash]
  );
  return rows[0];
}

async function findByEmail(email) {
  await init();
  if (useMemory) return mem.users.find((u) => u.email === email) || null;
  const { rows } = await getPool().query('SELECT * FROM users WHERE email = $1', [email]);
  return rows[0] || null;
}

async function findById(id) {
  await init();
  if (useMemory) {
    const u = mem.users.find((x) => String(x.id) === String(id));
    return u ? { id: u.id, name: u.name, email: u.email, created_at: u.created_at } : null;
  }
  const { rows } = await getPool().query(
    'SELECT id, name, email, created_at FROM users WHERE id = $1',
    [id]
  );
  return rows[0] || null;
}

module.exports = { createUser, findByEmail, findById, useMemory };
