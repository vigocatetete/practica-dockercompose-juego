const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = "supersecreto";

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

async function waitForDB() {
  let connected = false;
  while (!connected) {
    try {
      await pool.query('SELECT 1');
      connected = true;
      console.log("Conectado a PostgreSQL");
    } catch {
      console.log("Esperando a PostgreSQL...");
      await new Promise(res => setTimeout(res, 2000));
    }
  }
}

async function initDB() {
  await waitForDB();

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(100),
      password VARCHAR(200) NOT NULL,
      best_score INT DEFAULT 0,
      games_played INT DEFAULT 0
    );
  `);
}

initDB();

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: "No token" });

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Token inválido" });
  }
}

/* ======================
   AUTH
====================== */

app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;

  const hash = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1,$2,$3) RETURNING id, username, email',
      [username, email, hash]
    );

    res.json({ message: "Usuario creado", user: result.rows[0] });
  } catch (err) {
    res.status(400).json({ message: "Usuario ya existe" });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query(
    'SELECT * FROM users WHERE username = $1',
    [username]
  );

  if (result.rows.length === 0)
    return res.status(400).json({ message: "Usuario no encontrado" });

  const user = result.rows[0];
  const valid = await bcrypt.compare(password, user.password);

  if (!valid)
    return res.status(400).json({ message: "Contraseña incorrecta" });

  const token = jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: "2h" }
  );

  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      email: user.email
    }
  });
});

/* ======================
   PROFILE
====================== */

app.get('/api/profile', authMiddleware, async (req, res) => {
  const result = await pool.query(
    'SELECT id, username, email, best_score, games_played FROM users WHERE id=$1',
    [req.user.id]
  );

  const user = result.rows[0];

  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    stats: {
      bestScore: user.best_score,
      gamesPlayed: user.games_played
    }
  });
});

/* ======================
   SCORES
====================== */

app.post('/api/scores', authMiddleware, async (req, res) => {
  const { score } = req.body;

  const result = await pool.query(
    'SELECT best_score, games_played FROM users WHERE id=$1',
    [req.user.id]
  );

  const user = result.rows[0];

  const newBest = Math.max(user.best_score, score);
  const newGames = user.games_played + 1;
  const isNewRecord = score > user.best_score;

  await pool.query(
    'UPDATE users SET best_score=$1, games_played=$2 WHERE id=$3',
    [newBest, newGames, req.user.id]
  );

  res.json({
    message: "Score guardado",
    isNewRecord
  });
});

app.get('/api/scores', async (req, res) => {
  const limit = parseInt(req.query.limit) || 10;

  const result = await pool.query(
    'SELECT username, best_score as score FROM users ORDER BY best_score DESC LIMIT $1',
    [limit]
  );

  res.json(result.rows);
});

app.listen(3000, () => {
  console.log("Servidor corriendo en puerto 3000");
});