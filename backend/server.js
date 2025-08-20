const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const XLSX = require('xlsx');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_super_secret_change_me';
const TOKEN_EXPIRES_IN = process.env.TOKEN_EXPIRES_IN || '2h';

app.use(cors());
app.use(express.json());

const EXCEL_PATH = path.join(__dirname, 'users.xlsx');
const SHEET_NAME = 'Users';

function ensureWorkbook() {
  if (!fs.existsSync(EXCEL_PATH)) {
    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.json_to_sheet([]);
    XLSX.utils.book_append_sheet(wb, ws, SHEET_NAME);
    XLSX.writeFile(wb, EXCEL_PATH);
  }
}

function readUsers() {
  ensureWorkbook();
  const wb = XLSX.readFile(EXCEL_PATH);
  const ws = wb.Sheets[SHEET_NAME] || XLSX.utils.json_to_sheet([]);
  const data = XLSX.utils.sheet_to_json(ws);
  return data;
}

function writeUsers(users) {
  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.json_to_sheet(users);
  XLSX.utils.book_append_sheet(wb, ws, SHEET_NAME);
  XLSX.writeFile(wb, EXCEL_PATH);
}

// Helpers
function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function createToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRES_IN });
}

function authMiddleware(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ ok: false, message: 'Token requerido' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ ok: false, message: 'Token inválido o vencido' });
  }
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, message: 'API ok', time: new Date().toISOString() });
});

app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ ok: false, message: 'Nombre, correo y contraseña son obligatorios.' });
    }
    const emailNorm = normalizeEmail(email);
    const users = readUsers();

    const exists = users.find(u => normalizeEmail(u.email) === emailNorm);
    if (exists) {
      return res.status(409).json({ ok: false, message: 'Este correo ya está registrado.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const now = new Date().toISOString();

    const newUser = { name, email: emailNorm, passwordHash, createdAt: now };
    users.push(newUser);
    writeUsers(users);

    return res.status(201).json({ ok: true, message: 'Usuario registrado con éxito.' });
  } catch (err) {
    console.error('REGISTER_ERROR', err);
    return res.status(500).json({ ok: false, message: 'Error del servidor.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ ok: false, message: 'Correo y contraseña son obligatorios.' });
    }
    const emailNorm = normalizeEmail(email);
    const users = readUsers();
    const user = users.find(u => normalizeEmail(u.email) === emailNorm);
    if (!user) {
      return res.status(400).json({ ok: false, message: 'Credenciales inválidas.' });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      return res.status(400).json({ ok: false, message: 'Credenciales inválidas.' });
    }

    const token = createToken({ email: user.email, name: user.name });
    return res.json({ ok: true, token, user: { name: user.name, email: user.email } });
  } catch (err) {
    console.error('LOGIN_ERROR', err);
    return res.status(500).json({ ok: false, message: 'Error del servidor.' });
  }
});

app.get('/api/profile', authMiddleware, (req, res) => {
  res.json({ ok: true, user: req.user });
});

// Serve static frontend if placed in /public (optional)
// app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
