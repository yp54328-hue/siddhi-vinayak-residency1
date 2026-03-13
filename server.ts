import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());
  app.use(cors());

  // Database setup
  const db = await open({
    filename: './database.sqlite',
    driver: sqlite3.Database
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      flat_number TEXT NOT NULL,
      phone TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      role TEXT NOT NULL DEFAULT 'member',
      password TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      date TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS complaints (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      member_id INTEGER NOT NULL,
      complaint_text TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      date TEXT NOT NULL,
      FOREIGN KEY (member_id) REFERENCES members (id)
    );

    CREATE TABLE IF NOT EXISTS maintenance (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      member_id INTEGER NOT NULL,
      amount REAL NOT NULL,
      due_date TEXT NOT NULL,
      payment_status TEXT NOT NULL DEFAULT 'unpaid',
      FOREIGN KEY (member_id) REFERENCES members (id)
    );

    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      event_date TEXT NOT NULL
    );
  `);

  // Seed admin if not exists
  const adminExists = await db.get('SELECT * FROM members WHERE role = ?', 'admin');
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash('admin123', 10);
    await db.run(
      'INSERT INTO members (name, flat_number, phone, email, role, password) VALUES (?, ?, ?, ?, ?, ?)',
      ['Admin', '000', '0000000000', 'admin@example.com', 'admin', hashedPassword]
    );
  }

  // Auth Middleware
  const authenticateToken = (req: any, res: any, next: any) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
      if (err) return res.sendStatus(403);
      (req as any).user = user;
      next();
    });
  };

  const isAdmin = (req: any, res: any, next: any) => {
    if ((req as any).user.role !== 'admin') return res.sendStatus(403);
    next();
  };

  // Auth Routes
  app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await db.get('SELECT * FROM members WHERE email = ?', email);

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET);
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, flat_number: user.flat_number } });
  });

  // Members API
  app.get('/api/members', authenticateToken, isAdmin, async (req, res) => {
    const members = await db.all('SELECT id, name, flat_number, phone, email, role FROM members');
    res.json(members);
  });

  app.post('/api/members', authenticateToken, isAdmin, async (req, res) => {
    const { name, flat_number, phone, email, role, password } = req.body;
    const hashedPassword = await bcrypt.hash(password || 'member123', 10);
    try {
      await db.run(
        'INSERT INTO members (name, flat_number, phone, email, role, password) VALUES (?, ?, ?, ?, ?, ?)',
        [name, flat_number, phone, email, role || 'member', hashedPassword]
      );
      res.status(201).json({ message: 'Member added' });
    } catch (e) {
      res.status(400).json({ message: 'Email already exists' });
    }
  });

  app.put('/api/members/:id', authenticateToken, async (req, res) => {
    const { name, flat_number, phone, email } = req.body;
    const { id } = req.params;
    
    // Only admin or the user themselves can update
    if ((req as any).user.role !== 'admin' && (req as any).user.id !== parseInt(id)) {
      return res.sendStatus(403);
    }

    await db.run(
      'UPDATE members SET name = ?, flat_number = ?, phone = ?, email = ? WHERE id = ?',
      [name, flat_number, phone, email, id]
    );
    res.json({ message: 'Member updated' });
  });

  app.delete('/api/members/:id', authenticateToken, isAdmin, async (req, res) => {
    await db.run('DELETE FROM members WHERE id = ?', req.params.id);
    res.json({ message: 'Member deleted' });
  });

  // Notices API
  app.get('/api/notices', authenticateToken, async (req, res) => {
    const notices = await db.all('SELECT * FROM notices ORDER BY date DESC');
    res.json(notices);
  });

  app.post('/api/notices', authenticateToken, isAdmin, async (req, res) => {
    const { title, description } = req.body;
    const date = new Date().toISOString();
    await db.run('INSERT INTO notices (title, description, date) VALUES (?, ?, ?)', [title, description, date]);
    res.status(201).json({ message: 'Notice published' });
  });

  app.delete('/api/notices/:id', authenticateToken, isAdmin, async (req, res) => {
    await db.run('DELETE FROM notices WHERE id = ?', req.params.id);
    res.json({ message: 'Notice deleted' });
  });

  // Complaints API
  app.get('/api/complaints', authenticateToken, async (req, res) => {
    if ((req as any).user.role === 'admin') {
      const complaints = await db.all(`
        SELECT c.*, m.name as member_name, m.flat_number 
        FROM complaints c 
        JOIN members m ON c.member_id = m.id 
        ORDER BY date DESC
      `);
      res.json(complaints);
    } else {
      const complaints = await db.all('SELECT * FROM complaints WHERE member_id = ? ORDER BY date DESC', (req as any).user.id);
      res.json(complaints);
    }
  });

  app.post('/api/complaints', authenticateToken, async (req, res) => {
    const { complaint_text } = req.body;
    const date = new Date().toISOString();
    await db.run('INSERT INTO complaints (member_id, complaint_text, date) VALUES (?, ?, ?)', [(req as any).user.id, complaint_text, date]);
    res.status(201).json({ message: 'Complaint submitted' });
  });

  app.patch('/api/complaints/:id', authenticateToken, isAdmin, async (req, res) => {
    const { status } = req.body;
    await db.run('UPDATE complaints SET status = ? WHERE id = ?', [status, req.params.id]);
    res.json({ message: 'Complaint status updated' });
  });

  // Maintenance API
  app.get('/api/maintenance', authenticateToken, async (req, res) => {
    if ((req as any).user.role === 'admin') {
      const maintenance = await db.all(`
        SELECT mt.*, m.name as member_name, m.flat_number 
        FROM maintenance mt 
        JOIN members m ON mt.member_id = m.id 
        ORDER BY due_date DESC
      `);
      res.json(maintenance);
    } else {
      const maintenance = await db.all('SELECT * FROM maintenance WHERE member_id = ? ORDER BY due_date DESC', (req as any).user.id);
      res.json(maintenance);
    }
  });

  app.post('/api/maintenance', authenticateToken, isAdmin, async (req, res) => {
    const { member_id, amount, due_date } = req.body;
    await db.run('INSERT INTO maintenance (member_id, amount, due_date) VALUES (?, ?, ?)', [member_id, amount, due_date]);
    res.status(201).json({ message: 'Bill generated' });
  });

  app.patch('/api/maintenance/:id', authenticateToken, isAdmin, async (req, res) => {
    const { payment_status } = req.body;
    await db.run('UPDATE maintenance SET payment_status = ? WHERE id = ?', [payment_status, req.params.id]);
    res.json({ message: 'Payment status updated' });
  });

  // Events API
  app.get('/api/events', authenticateToken, async (req, res) => {
    const events = await db.all('SELECT * FROM events ORDER BY event_date ASC');
    res.json(events);
  });

  app.post('/api/events', authenticateToken, isAdmin, async (req, res) => {
    const { title, description, event_date } = req.body;
    await db.run('INSERT INTO events (title, description, event_date) VALUES (?, ?, ?)', [title, description, event_date]);
    res.status(201).json({ message: 'Event scheduled' });
  });

  app.delete('/api/events/:id', authenticateToken, isAdmin, async (req, res) => {
    await db.run('DELETE FROM events WHERE id = ?', req.params.id);
    res.json({ message: 'Event deleted' });
  });

  // Stats API for Admin
  app.get('/api/stats', authenticateToken, isAdmin, async (req, res) => {
    const totalMembers = await db.get('SELECT COUNT(*) as count FROM members WHERE role = "member"');
    const totalComplaints = await db.get('SELECT COUNT(*) as count FROM complaints WHERE status = "pending"');
    const totalNotices = await db.get('SELECT COUNT(*) as count FROM notices');
    const unpaidMaintenance = await db.get('SELECT COUNT(*) as count FROM maintenance WHERE payment_status = "unpaid"');
    
    res.json({
      totalMembers: totalMembers.count,
      pendingComplaints: totalComplaints.count,
      totalNotices: totalNotices.count,
      unpaidBills: unpaidMaintenance.count
    });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
