'use strict';
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const fetch = require('node-fetch');
const { v4: uuid } = require('uuid');
const XLSX = require('xlsx');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA = path.join(__dirname, 'data');
fs.mkdirSync(DATA, { recursive: true });
const UF = path.join(DATA, 'users.json');
const PF = path.join(DATA, 'projects.json');
const rj = (f, d) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch(e) { return d; } };
const wj = (f, d) => fs.writeFileSync(f, JSON.stringify(d, null, 2));

let users = rj(UF, []);
users = [];
if (!users.find(u => u.username === 'naim2')) {
  users.push({ id: uuid(), username: 'naim2', password_hash: bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'ni2026', 10), role: 'admin' });
  wj(UF, users);
}

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(session({ secret: process.env.SESSION_SECRET || 'ni-secret-key', resave: true, saveUninitialized: false, cookie: { secure: false, sameSite: 'lax', maxAge: 604800000 } }));const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20971520, files: 20 } });
const auth = (req, res, next) => req.session.userId ? next() : res.status(401).json({ error: 'Not authenticated' });
app.use(express.static(__dirname));

app.post('/api/login', (req, res) => {
  users = rj(UF, []);
  const u = users.find(u => u.username === req.body.username);
  if (!u || !bcrypt.compareSync(req.body.password, u.password_hash)) return res.status(401).json({ error: 'Invalid credentials' });
  req.session.userId = u.id; req.session.username = u.username; req.session.role = u.role;
  res.json({ ok: true, username: u.username, role: u.role });
});
app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json({ username: req.session.username, role: req.session.role }));

app.get('/api/projects', auth, (req, res) => {
  const all = rj(PF, []);
  res.json(all.filter(p => p.user_id === req.session.userId).sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at)));
});
app.post('/api/projects', auth, (req, res) => {
  const all = rj(PF, []);
  const p = { id: uuid(), user_id: req.session.userId, ...req.body, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
  all.push(p); wj(PF, all); res.json(p);
});
app.put('/api/projects/:id', auth, (req, res) => {
  const all = rj(PF, []);
  const i = all.findIndex(p => p.id === req.params.id && p.user_id === req.session.userId);
  if (i < 0) return res.status(404).json({ error: 'Not found' });
  all[i] = { ...all[i], ...req.body, updated_at: new Date().toISOString() };
  wj(PF, all); res.json(all[i]);
});
app.delete('/api/projects/:id', auth, (req, res) => {
  const all = rj(PF, []);
  wj(PF, all.filter(p => !(p.id === req.params.id && p.user_id === req.session.userId)));
  res.json({ ok: true });
});

app.post('/api/analyze', auth, upload.array('drawings', 20), async (req, res) => {
  if (!process.env.ANTHROPIC_API_KEY) return res.status(500).json({ error: 'ANTHROPIC_API_KEY not set' });
  if (!req.files || !req.files.length) return res.status(400).json({ error: 'No files' });
  try {
    const content = [];
    for (const f of req.files) {
      const b64 = f.buffer.toString('base64');
      if (f.mimetype === 'application/pdf') content.push({ type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: b64 } });
      else if (f.mimetype.startsWith('image/')) content.push({ type: 'image', source: { type: 'base64', media_type: f.mimetype, data: b64 } });
    }
    content.push({ type: 'text', text: PROMPT });
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-opus-4-5', max_tokens: 4000, messages: [{ role: 'user', content }] })
    });
    if (!r.ok) throw new Error('API error: ' + await r.text());
    const data = await r.json();
    const raw = data.content.map(b => b.text || '').join('');
    const m = raw.match(/```json\s*([\s\S]*?)\s*```/) || raw.match(/(\{[\s\S]*\})/);
    if (!m) throw new Error('Could not parse response');
    res.json({ ok: true, bidData: JSON.parse(m[1]) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/export/excel', auth, (req, res) => {
  const p = req.body;
  const sub = (p.divisions || []).reduce((s, d) => s + d.items.reduce((ss, it) => ss + (parseFloat(it.cost) || 0), 0), 0);
  const gc = Math.round(sub * (p.pct_gc || 8) / 100);
  const oh = Math.round(sub * (p.pct_oh || 10) / 100);
  const ins = Math.round(sub * (p.pct_ins || 8) / 100);
  const grand = sub + gc + oh + ins;
  const f = n => n ? '$' + Math.round(n).toLocaleString('en-US') : '';
  const wb = XLSX.utils.book_new();
  const rows = [['NI CONSTRUCTION CORP.'], ['Lic #2056165-DCA'], [], ['PROJECT:', p.address], ['ARCHITECT:', p.architect], ['PM:', p.pm], ['BID #:', p.bid_number], ['DATE:', p.date], [], ['DIV', 'LINE ITEM', 'REMARK', 'COST']];
  (p.divisions || []).forEach(div => {
    const dt = div.items.reduce((s, it) => s + (parseFloat(it.cost) || 0), 0);
    rows.push(['DIV ' + div.div, div.name, '', f(dt)]);
    div.items.forEach(it => rows.push(['', '  ' + it.name, it.remark || '', it.cost ? f(it.cost) : '']));
    rows.push([]);
  });
  rows.push(['', 'SUBTOTAL', '', f(sub)], ['', 'GC', '', f(gc)], ['', 'OH', '', f(oh)], ['', 'Ins', '', f(ins)], ['', 'GRAND TOTAL', '', f(grand)]);
  const ws = XLSX.utils.aoa_to_sheet(rows);
  ws['!cols'] = [{ wch: 8 }, { wch: 52 }, { wch: 22 }, { wch: 16 }];
  XLSX.utils.book_append_sheet(wb, ws, 'Proposal');
  const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', 'attachment; filename="NI-Bid-' + p.bid_number + '.xlsx"');
  res.send(buf);
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.listen(PORT, () => console.log('Running on ' + PORT + ' | key: ' + !!process.env.ANTHROPIC_API_KEY));

const PROMPT = 'You are an expert NYC construction estimator for NI Construction Corp. Analyze these drawings and generate a cost estimate using NYC pre-war building rates. RATE CARD: Site protection $5k-$12k, Demo gut $28-42/SF, Metal framing $8-12/SF, IKEA millwork $350-500/LF, Doors $800-1400 EA, GWB $10-16/SF, Tile labor $14-28/SF, Wood floor $12-18/SF, Paint $1.80-2.50/SF, Plumbing rough $2200-3800 EA, Electrical $22-35/SF. RESPOND ONLY WITH VALID JSON: {"project_address":"","architect":"","scope_summary":"description","line_items":[{"division":"02","division_name":"EXISTING CONDITIONS","name":"Site Protection","remark":"","cost":6500}]}';
