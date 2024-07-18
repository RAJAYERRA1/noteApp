const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const db = new sqlite3.Database(':memory:');
const PORT = 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// JWT Secret
const JWT_SECRET = 'your_jwt_secret';

// Create users table
db.run(`CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)`);

// Create notes table
db.run(`CREATE TABLE notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId INTEGER,
  title TEXT,
  content TEXT,
  tags TEXT,
  color TEXT,
  archived INTEGER DEFAULT 0,
  trashed INTEGER DEFAULT 0,
  reminder DATE,
  FOREIGN KEY(userId) REFERENCES users(id)
)`);

// Register endpoint
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);

  db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
    if (err) return res.status(500).send('User registration failed');
    res.status(200).send('User registered successfully');
  });
});

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err) return res.status(500).send('User authentication failed');
    if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).send('Invalid username or password');

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: 86400 });
    res.status(200).send({ auth: true, token });
  });
});

// Middleware to verify JWT
const verifyJWT = (req, res, next) => {
  const token = req.headers['x-access-token'];
  if (!token) return res.status(403).send('No token provided');

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(500).send('Failed to authenticate token');
    req.userId = decoded.id;
    next();
  });
};

// Create a new note
app.post('/notes', verifyJWT, (req, res) => {
  const { title, content, tags, color, reminder } = req.body;
  const userId = req.userId;
  
  db.run(`INSERT INTO notes (userId, title, content, tags, color, reminder) VALUES (?, ?, ?, ?, ?, ?)`, 
    [userId, title, content, tags.join(','), color, reminder], 
    function(err) {
      if (err) return res.status(500).send('Note creation failed');
      res.status(200).send({ id: this.lastID });
  });
});

// Get all notes
app.get('/notes', verifyJWT, (req, res) => {
  const userId = req.userId;

  db.all(`SELECT * FROM notes WHERE userId = ? AND trashed = 0`, [userId], (err, notes) => {
    if (err) return res.status(500).send('Failed to fetch notes');
    res.status(200).send(notes);
  });
});

// Get notes by tag
app.get('/notes/tag/:tag', verifyJWT, (req, res) => {
  const userId = req.userId;
  const tag = req.params.tag;

  db.all(`SELECT * FROM notes WHERE userId = ? AND tags LIKE ? AND trashed = 0`, [userId, `%${tag}%`], (err, notes) => {
    if (err) return res.status(500).send('Failed to fetch notes by tag');
    res.status(200).send(notes);
  });
});

// Archive note
app.put('/notes/:id/archive', verifyJWT, (req, res) => {
  const noteId = req.params.id;
  const userId = req.userId;

  db.run(`UPDATE notes SET archived = 1 WHERE id = ? AND userId = ?`, [noteId, userId], function(err) {
    if (err) return res.status(500).send('Failed to archive note');
    res.status(200).send('Note archived successfully');
  });
});

// Trash note
app.put('/notes/:id/trash', verifyJWT, (req, res) => {
  const noteId = req.params.id;
  const userId = req.userId;

  db.run(`UPDATE notes SET trashed = 1 WHERE id = ? AND userId = ?`, [noteId, userId], function(err) {
    if (err) return res.status(500).send('Failed to trash note');
    res.status(200).send('Note trashed successfully');
  });
});

// Get trashed notes
app.get('/notes/trashed', verifyJWT, (req, res) => {
  const userId = req.userId;

  db.all(`SELECT * FROM notes WHERE userId = ? AND trashed = 1 AND date('now', '-30 days') <= date('reminder')`, [userId], (err, notes) => {
    if (err) return res.status(500).send('Failed to fetch trashed notes');
    res.status(200).send(notes);
  });
});

// Get notes with reminders
app.get('/notes/reminders', verifyJWT, (req, res) => {
  const userId = req.userId;

  db.all(`SELECT * FROM notes WHERE userId = ? AND reminder IS NOT NULL AND date('now') <= date(reminder)`, [userId], (err, notes) => {
    if (err) return res.status(500).send('Failed to fetch notes with reminders');
    res.status(200).send(notes);
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
