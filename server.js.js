const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = req.cookies.token || (authHeader && authHeader.split(' ')[1]);
  if (!token) return res.status(401).json({ error: 'Access denied.' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired token.' });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin access required.' });
  next();
};

// Authentication Endpoints
app.post('/api/auth/register', async (req, res) => {
  const { fullName, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    const accountNumber = Math.floor(100000000000 + Math.random() * 900000000000).toString();

    const userRes = await pool.query(
      `INSERT INTO users (full_name, email, password_hash, account_number) 
       VALUES ($1, $2, $3, $4) RETURNING id, full_name, email, account_number, role`,
      [fullName, email, hashedPassword, accountNumber]
    );
    
    await pool.query(`INSERT INTO accounts (user_id, balance) VALUES ($1, $2)`, [userRes.rows[0].id, 0.00]);
    res.status(201).json({ message: 'User registered successfully', user: userRes.rows[0] });
  } catch (err) {
    res.status(400).json({ error: 'Registration failed. Email may already exist.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    if (user.is_frozen) return res.status(403).json({ error: 'Account is frozen.' });

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

    await pool.query('INSERT INTO login_history (user_id, ip_address, user_agent) VALUES ($1, $2, $3)',
      [user.id, req.ip, req.headers['user-agent']]
    );

    const token = jwt.sign({ id: user.id, role: user.role, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
    res.json({ message: 'Login successful', role: user.role, token });
  } catch (err) {
    res.status(500).json({ error: 'Server error during login.' });
  }
});

// User Dashboard Endpoint
app.get('/api/user/dashboard', authenticateToken, async (req, res) => {
  try {
    const userRes = await pool.query(
      `SELECT u.full_name, u.email, u.account_number, a.balance 
       FROM users u JOIN accounts a ON u.id = a.user_id WHERE u.id = $1`, [req.user.id]
    );
    const txRes = await pool.query(
      `SELECT t.type, t.amount, t.description, t.created_at 
       FROM transactions t JOIN accounts a ON t.account_id = a.id 
       WHERE a.user_id = $1 ORDER BY t.created_at DESC LIMIT 10`, [req.user.id]
    );
    res.json({ profile: userRes.rows[0], transactions: txRes.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch dashboard data.' });
  }
});

// Admin Panel Endpoints
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  const { search } = req.query;
  try {
    let queryText = `SELECT u.id, u.full_name, u.email, u.account_number, u.is_frozen, u.role, a.balance FROM users u LEFT JOIN accounts a ON u.id = a.user_id`;
    let params = [];
    if (search) {
      queryText += ` WHERE u.full_name ILIKE $1 OR u.email ILIKE $1 OR u.account_number ILIKE $1`;
      params.push(`%${search}%`);
    }
    queryText += ` ORDER BY u.created_at DESC`;

    const users = await pool.query(queryText, params);
    const stats = await pool.query(`
      SELECT COUNT(u.id) AS total_users, COALESCE(SUM(a.balance), 0) AS total_balances
      FROM users u LEFT JOIN accounts a ON u.id = a.user_id
    `);

    res.json({ stats: stats.rows[0], users: users.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch admin data.' });
  }
});

app.post('/api/admin/transaction', authenticateToken, requireAdmin, async (req, res) => {
  const { userId, type, amount, description } = req.body;
  const numericAmount = parseFloat(amount);
  if (isNaN(numericAmount) || numericAmount <= 0) return res.status(400).json({ error: 'Invalid amount.' });

  try {
    const accRes = await pool.query('SELECT id, balance FROM accounts WHERE user_id = $1', [userId]);
    if (accRes.rows.length === 0) return res.status(404).json({ error: 'Account not found.' });

    const account = accRes.rows[0];
    let newBalance = parseFloat(account.balance);

    if (type === 'DEBIT') {
      if (newBalance < numericAmount) return res.status(400).json({ error: 'Insufficient funds.' });
      newBalance -= numericAmount;
    } else if (type === 'CREDIT') {
      newBalance += numericAmount;
    } else {
      return res.status(400).json({ error: 'Invalid type.' });
    }

    await pool.query('UPDATE accounts SET balance = $1, updated_at = NOW() WHERE id = $2', [newBalance, account.id]);
    await pool.query('INSERT INTO transactions (account_id, type, amount, description) VALUES ($1, $2, $3, $4)', [account.id, type, numericAmount, description]);

    res.json({ message: 'Transaction processed successfully.', newBalance });
  } catch (err) {
    res.status(500).json({ error: 'Transaction failed.' });
  }
});

app.patch('/api/admin/users/:id/freeze', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE users SET is_frozen = $1 WHERE id = $2', [req.body.isFrozen, req.params.id]);
    res.json({ message: 'Account status updated.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update status.' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server live on port ${PORT}`));
