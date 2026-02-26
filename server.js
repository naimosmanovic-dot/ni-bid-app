'use strict';
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const multer  = require('multer');
const bcrypt  = require('bcryptjs');
const path    = require('path');
const fs      = require('fs');
const fetch   = require('node-fetch');
const { v4: uuid } = require('uuid');
const XLSX    = require('xlsx');

const app  = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const USERS_FILE    = path.join(DATA_DIR, 'users.json');
const PROJECTS_FILE = path.join(DATA_DIR, 'projects.json');

function readJSON(file, def) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch(e) { return def; }
}
function writeJSON(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }

let users = readJSON(USERS_FILE, []);
if (!users.find(u => u.username === 'naim')) {
  users.push({ id: uuid(), username: 'naim', password_hash: bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'ni2026secure', 10), role: 'admin' });
  writeJSON(USERS_FILE, users);
  console.log('Created user: naim');
}

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(session({ secret: process.env.SESSION_SECRET || 'ni-secret', resave: false, saveUninitialized: false, cookie: { secure: false, maxAge: 7*24*60*60*1000 } }));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20*1024*1024, files: 20 } });
const requireAuth = (req, res, next) => req.session?.userId ? next() : res.status(401).json({ error: 'Not authenticated' });

app.use(express.static(path.join(__dirname)));

app.post('/api/login', (req, res) => {
  users = readJSON(USERS_FILE, []);
  const user = users.find(u => u.username === req.body.username);
  if (!user || !bcrypt.compareSync(req.body.password, user.password_hash)) return res.status(401).json({ error: 'Invalid credentials' });
  req.session.userId = user.id; req.session.username = user.username; req.session.role = user.role;
  res.json({ ok: true, username: user.username, role: user.role });
});
app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });
app.get('/api/me', requireAuth, (req, res) => res.json({ username: req.session.username, role: req.session.role }));

app.get('/api/projects', requireAuth, (req, res) => {
  const all = readJSON(PROJECTS_FILE, []);
  res.json(all.filter(p => p.user_id === req.session.userId).sort((a,b) => new Date(b.updated_at)-new Date(a.updated_at)));
});
app.post('/api/projects', requireAuth, (req, res) => {
  const all = readJSON(PROJECTS_FILE, []);
  const p = { id: uuid(), user_id: req.session.userId, ...req.body, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
  all.push(p); writeJSON(PROJECTS_FILE, all); res.json(p);
});
app.put('/api/projects/:id', requireAuth, (req, res) => {
  let all = readJSON(PROJECTS_FILE, []);
  const idx = all.findIndex(p => p.id === req.params.id && p.user_id === req.session.userId);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  all[idx] = { ...all[idx], ...req.body, updated_at: new Date().toISOString() };
  writeJSON(PROJECTS_FILE, all); res.json(all[idx]);
});
app.delete('/api/projects/:id', requireAuth, (req, res) => {
  let all = readJSON(PROJECTS_FILE, []);
  writeJSON(PROJECTS_FILE, all.filter(p => !(p.id === req.params.id && p.user_id === req.session.userId)));
  res.json({ ok: true });
});

app.post('/api/analyze', requireAuth, upload.array('drawings', 20), async (req, res) => {
  if (!process.env.ANTHROPIC_API_KEY) return res.status(500).json({ error: 'ANTHROPIC_API_KEY not set' });
  if (!req.files?.length) return res.status(400).json({ error: 'No files uploaded' });
  try {
    const content = [];
    for (const file of req.files) {
      const b64 = file.buffer.toString('base64');
      if (file.mimetype === 'application/pdf') content.push({ type:'document', source:{ type:'base64', media_type:'application/pdf', data:b64 }});
      else if (file.mimetype.startsWith('image/')) content.push({ type:'image', source:{ type:'base64', media_type:file.mimetype, data:b64 }});
    }
    content.push({ type:'text', text: PROMPT });
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method:'POST',
      headers:{ 'Content-Type':'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version':'2023-06-01' },
