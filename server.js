const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const db = new Database('database.db');

// ---------- СХЕМА БД ----------
db.exec(`
  CREATE TABLE IF NOT EXISTS rooms (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    capacity INTEGER NOT NULL,
    price INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id INTEGER NOT NULL,
    guest_name TEXT NOT NULL,
    guest_email TEXT NOT NULL,
    check_in TEXT NOT NULL,
    check_out TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    FOREIGN KEY(room_id) REFERENCES rooms(id)
  );
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  );
`);

// Начальные номера
if (db.prepare('SELECT COUNT(*) AS c FROM rooms').get().c === 0) {
  const ins = db.prepare('INSERT INTO rooms (type,title,capacity,price) VALUES (?,?,?,?)');
  [
    ['standard', 'Стандарт с видом на город', 2, 3200],
    ['standard', 'Стандарт твин', 2, 2900],
    ['comfort', 'Комфорт с балконом', 3, 4800],
    ['comfort', 'Комфорт семейный', 4, 5400],
    ['lux', 'Люкс «Сладкий сон»', 2, 8900],
    ['lux', 'Люкс президентский', 4, 13500]
  ].forEach(r => ins.run(r[0], r[1], r[2], r[3]));
}

// Начальный админ
if (db.prepare('SELECT COUNT(*) AS c FROM admins').get().c === 0) {
  const hash = bcrypt.hashSync('adminHotel', 10);
  db.prepare('INSERT INTO admins (username,password_hash) VALUES (?,?)').run('hotel123', hash);
}

// ---------- MIDDLEWARE ----------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'change-me-in-production-super-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 4 }
}));
app.use(express.static(path.join(__dirname, 'public')));

function requireAdmin(req, res, next) {
  if (req.session && req.session.admin) return next();
  res.status(401).json({ error: 'Требуется авторизация' });
}

function validateDate(str) {
  return typeof str === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(str);
}

function todayISO() {
  const d = new Date();
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}

// ---------- API ГOСТЯ ----------
app.get('/api/rooms', (req, res) => {
  const { type, maxPrice, capacity } = req.query;
  let sql = 'SELECT * FROM rooms WHERE 1=1';
  const params = [];
  if (type) { sql += ' AND type = ?'; params.push(type); }
  if (maxPrice) { sql += ' AND price <= ?'; params.push(Number(maxPrice)); }
  if (capacity) { sql += ' AND capacity >= ?'; params.push(Number(capacity)); }
  res.json(db.prepare(sql).all(...params));
});

app.get('/api/rooms/:id/busy', (req, res) => {
  const roomId = Number(req.params.id);
  const rows = db.prepare("SELECT check_in, check_out FROM bookings WHERE room_id = ? AND status = 'approved'").all(roomId);
  const busy = [];
  for (const row of rows) {
    const cur = new Date(row.check_in);
    const end = new Date(row.check_out);
    while (cur < end) {
      busy.push(cur.toISOString().slice(0, 10));
      cur.setDate(cur.getDate() + 1);
    }
  }
  res.json(busy);
});

app.post('/api/bookings', (req, res) => {
  const { roomId, guestName, guestEmail, checkIn, checkOut } = req.body || {};
  const errors = [];

  if (!guestName || guestName.trim().length < 2) errors.push('Имя минимум 2 символа');
  if (!guestEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(guestEmail)) errors.push('Некорректный email');
  if (!validateDate(checkIn)) errors.push('Некорректная дата заезда');
  if (!validateDate(checkOut)) errors.push('Некорректная дата выезда');

  const today = todayISO();
  if (validateDate(checkIn) && checkIn < today) errors.push('Дата заезда не может быть в прошлом');
  if (validateDate(checkIn) && validateDate(checkOut) && checkOut <= checkIn) {
    errors.push('Дата выезда должна быть позже даты заезда');
  }

  const room = db.prepare('SELECT * FROM rooms WHERE id = ?').get(Number(roomId));
  if (!room) errors.push('Номер не найден');

  if (room && !errors.length) {
    const clash = db.prepare(`
      SELECT 1 FROM bookings
      WHERE room_id = ? AND status = 'approved'
        AND NOT (check_out <= ? OR check_in >= ?)
    `).get(room.id, checkIn, checkOut);
    if (clash) errors.push('Выбранный период уже забронирован');
  }

  if (errors.length) return res.status(400).json({ errors });

  const info = db.prepare(`
    INSERT INTO bookings (room_id, guest_name, guest_email, check_in, check_out, status, created_at)
    VALUES (?, ?, ?, ?, ?, 'pending', ?)
  `).run(room.id, guestName.trim(), guestEmail.trim(), checkIn, checkOut, new Date().toISOString());

  res.json({ id: info.lastInsertRowid, message: 'Заявка создана' });
});

// ---------- АВТОРИЗАЦИЯ АДМИНА ----------
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
  if (!admin || !bcrypt.compareSync(password, admin.password_hash)) {
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }
  req.session.admin = { id: admin.id, username: admin.username };
  res.json({ ok: true, username: admin.username });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/admin/me', (req, res) => {
  if (req.session && req.session.admin) return res.json({ admin: req.session.admin });
  res.status(401).json({ error: 'Не авторизован' });
});

// ---------- API АДМИНА ----------
app.get('/api/admin/bookings', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT b.*, r.title AS room_title
    FROM bookings b JOIN rooms r ON r.id = b.room_id
    ORDER BY b.id DESC
  `).all();
  res.json(rows);
});

app.post('/api/admin/bookings/:id/approve', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const b = db.prepare('SELECT * FROM bookings WHERE id = ?').get(id);
  if (!b) return res.status(404).json({ error: 'Заявка не найдена' });
  if (b.status !== 'pending') return res.status(400).json({ error: 'Заявка уже обработана' });

  const clash = db.prepare(`
    SELECT 1 FROM bookings
    WHERE room_id = ? AND status = 'approved' AND id != ?
      AND NOT (check_out <= ? OR check_in >= ?)
  `).get(b.room_id, id, b.check_in, b.check_out);
  if (clash) return res.status(409).json({ error: 'Период пересекается с одобренной бронью' });

  db.prepare("UPDATE bookings SET status='approved' WHERE id=?").run(id);
  res.json({ ok: true });
});

app.delete('/api/admin/bookings/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const info = db.prepare('DELETE FROM bookings WHERE id = ?').run(id);
  if (info.changes === 0) return res.status(404).json({ error: 'Заявка не найдена' });
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер запущен: http://localhost:${PORT}`));