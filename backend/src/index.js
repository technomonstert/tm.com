require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));
app.use(helmet());
app.use(express.json());

// Simple rate limiter (5 req per minute per IP on auth routes)
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: 'Too many attempts, try again later.' }
});

// In‑memory user store removed – we now use PostgreSQL users table
let users = [];


app.get('/health', (req, res) => res.json({ status: 'OK' }));

app.post('/register', authLimiter, async (req, res) => {
  const { email, password, firstName, lastName } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  const exists = users.find(u => u.email === email);
  if (exists) return res.status(409).json({ error: 'User exists' });
  const salt = await bcrypt.genSalt(12);
  const hash = await bcrypt.hash(password, salt);
  const newUser = { id: users.length + 1, email, passwordHash: hash, firstName, lastName };
  users.push(newUser);
  const token = jwt.sign({ sub: newUser.id, email }, process.env.JWT_SECRET, { expiresIn: '15m' });
  const refresh = jwt.sign({ sub: newUser.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, refresh });
});

app.post('/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ sub: user.id, email }, process.env.JWT_SECRET, { expiresIn: '15m' });
  const refresh = jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, refresh });
});

// Ensure required tables exist
(async () => {
  try {
    // users table (already used in-memory earlier, now store basic fields)
    await db.query(`CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      first_name VARCHAR(100),
      last_name VARCHAR(100)
    );`);
    await db.query(`CREATE TABLE IF NOT EXISTS plans (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      price_cents INTEGER NOT NULL,
      data_cap_gb INTEGER,
      speed_mbps INTEGER,
      description TEXT
    );`);
    await db.query(`CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      plan_id INTEGER REFERENCES plans(id),
      amount_cents INTEGER NOT NULL,
      stripe_payment_intent_id VARCHAR(255),
      status VARCHAR(20) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`);
    console.log('Database tables ensured.');
  } catch (e) {
    console.error('Error ensuring DB tables', e);
  }
})();


// Serve static frontend (built later) from /public
app.use(express.static('public'));

// ---------- Additional API routes ----------
const db = require('./db');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Helper: verify JWT and attach user payload
// JWT already imported at top
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user; // { sub, email }
    next();
  });
};

// ----- Plans -----
app.get('/api/plans', async (req, res) => {
  try {
    const { rows } = await db.query('SELECT id, name, price_cents, data_cap_gb, speed_mbps, description FROM plans ORDER BY id');
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to fetch plans' });
  }
});

// ----- Checkout (Stripe) -----
app.post('/api/checkout', authMiddleware, async (req, res) => {
  const { planId } = req.body;
  if (!planId) return res.status(400).json({ error: 'planId required' });
  try {
    const { rows } = await db.query('SELECT price_cents, name FROM plans WHERE id=$1', [planId]);
    if (rows.length === 0) return res.status(404).json({ error: 'Plan not found' });
    const plan = rows[0];
    const paymentIntent = await stripe.paymentIntents.create({
      amount: plan.price_cents,
      currency: 'usd',
      metadata: { planId, userId: req.user.sub, planName: plan.name },
    });
    // Record order in DB (pending)
    await db.query(
      'INSERT INTO orders (user_id, plan_id, amount_cents, stripe_payment_intent_id, status) VALUES ($1,$2,$3,$4,$5)',
      [req.user.sub, planId, plan.price_cents, paymentIntent.id, 'pending']
    );
    res.json({ clientSecret: paymentIntent.client_secret });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

// ----- Admin routes (simple role check) -----
const adminMiddleware = (req, res, next) => {
  // Very simple admin check – email matches admin@example.com (replace as needed)
  if (req.user && req.user.email && req.user.email.endsWith('@admin.com')) {
    return next();
  }
  return res.status(403).json({ error: 'Admin only' });
};

app.post('/api/admin/plan', authMiddleware, adminMiddleware, async (req, res) => {
  const { name, price_cents, data_cap_gb, speed_mbps, description } = req.body;
  if (!name || !price_cents) return res.status(400).json({ error: 'Missing fields' });
  try {
    const { rows } = await db.query(
      'INSERT INTO plans (name, price_cents, data_cap_gb, speed_mbps, description) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [name, price_cents, data_cap_gb, speed_mbps, description]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to create plan' });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Backend listening on port ${PORT}`));
