// server.js (versão corrigida e mais robusta)
require('dotenv').config(); // opcional - se usar .env
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const mysql = require("mysql2/promise");
const { Server } = require("socket.io");
const http = require("http");
const path = require("path");
const os = require("os");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Config (pode usar .env ou editar aqui)
const PORT = process.env.PORT || 3000;
const DB_HOST = process.env.DB_HOST || "localhost";
const DB_USER = process.env.DB_USER || "root";
const DB_PASS = process.env.DB_PASS || "";
const DB_NAME = process.env.DB_NAME || "chatbombinha";
const SESSION_SECRET = process.env.SESSION_SECRET || "bombinha-super-secreto";

// Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30*24*60*60*1000 }
}));

// Servir arquivos estáticos da pasta /public
app.use(express.static(path.join(__dirname, "public")));

// Rota raiz redireciona para login
app.get("/", (req, res) => {
  res.redirect("/login.html");
});

// Pool do MySQL
let db = null;
async function initDb() {
  db = await mysql.createPool({
    host: DB_HOST,
    user: DB_USER,
    password: DB_PASS,
    database: DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

  await db.query("SELECT 1"); // Testa conexão
  console.log("✅ Conexão com MySQL estabelecida (database:", DB_NAME + ")");
}

// ---------- Rotas de autenticação ----------
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send("Usuário/senha obrigatório");

    const [exists] = await db.query("SELECT id FROM users WHERE username = ?", [username]);
    if (exists.length) return res.status(400).send("Usuário já existe! <a href='/register.html'>Voltar</a>");

    const hash = await bcrypt.hash(password, 10);
    await db.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash]);
    return res.redirect("/login.html");
  } catch (err) {
    console.error("Erro /register:", err);
    return res.status(500).send("Erro interno");
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send("Usuário/senha obrigatório");

    const [rows] = await db.query("SELECT * FROM users WHERE username = ?", [username]);
    if (rows.length === 0) return res.status(401).send("Login inválido! <a href='/login.html'>Tentar novamente</a>");

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).send("Login inválido! <a href='/login.html'>Tentar novamente</a>");

    req.session.userId = user.id;
    req.session.username = user.username;
    return res.redirect("/chat.html");
  } catch (err) {
    console.error("Erro /login:", err);
    return res.status(500).send("Erro interno");
  }
});

// Rota para pegar dados do usuário logado
app.get("/me", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Não logado" });
  res.json({ userId: req.session.userId, username: req.session.username });
});

// ---------- Rotas de salas ----------
app.get("/rooms", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT id, name, password FROM rooms ORDER BY id DESC");
    res.json(rows.map(r => ({ id: r.id, name: r.name, private: !!r.password })));
  } catch (err) {
    console.error("Erro /rooms GET:", err);
    res.status(500).json({ error: "Erro ao listar salas" });
  }
});

app.post("/rooms", async (req, res) => {
  try {
    const { name, password } = req.body;
    if (!name || name.trim().length === 0) return res.status(400).json({ error: "Nome da sala é obrigatório" });

    const [exists] = await db.query("SELECT id FROM rooms WHERE name = ?", [name]);
    if (exists.length) return res.status(400).json({ error: "Sala já existe" });

    let hash = null;
    if (password && password.trim().length > 0) {
      hash = await bcrypt.hash(password, 10);
    }

    await db.query("INSERT INTO rooms (name, password) VALUES (?, ?)", [name, hash]);
    res.json({ success: true });
  } catch (err) {
    console.error("Erro /rooms POST:", err);
    res.status(500).json({ error: "Erro ao criar sala" });
  }
});

app.post("/join-room", async (req, res) => {
  try {
    const { name, password } = req.body;
    if (!name) return res.status(400).json({ error: "Nome da sala obrigatório" });

    const [rows] = await db.query("SELECT * FROM rooms WHERE name = ?", [name]);
    if (rows.length === 0) return res.status(404).json({ error: "Sala não encontrada" });

    const room = rows[0];
    if (room.password) {
      const valid = await bcrypt.compare(password || "", room.password);
      if (!valid) return res.status(403).json({ error: "Senha incorreta" });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Erro /join-room:", err);
    res.status(500).json({ error: "Erro ao entrar na sala" });
  }
});

// ---------- WebSocket (Socket.IO) ----------
io.on("connection", (socket) => {
  console.log("🟢 Novo socket conectado:", socket.id);

  socket.on("joinRoom", async (room) => {
    if (!room) return;
    socket.join(room);
    socket.room = room;
    console.log(`Socket ${socket.id} entrou na sala ${room}`);

    // Histórico
    try {
      const [msgs] = await db.query(
        `SELECT m.message, m.created_at, u.username
         FROM messages m
         JOIN users u ON m.user_id = u.id
         WHERE m.room = ?
         ORDER BY m.created_at DESC
         LIMIT 50`, [room]
      );
      socket.emit("history", msgs.reverse());
    } catch (err) {
      console.warn("Não foi possível carregar histórico:", err);
    }

    io.to(room).emit("message", { username: "Sistema", msg: `Usuário entrou na sala.` });
  });

  socket.on("chatMessage", async (msg, userId, username) => {
    if (!socket.room) return;
    if (!msg || typeof msg !== "string" || msg.trim().length === 0) return;

    try {
      await db.query("INSERT INTO messages (user_id, room, message) VALUES (?, ?, ?)", [userId, socket.room, msg]);
    } catch (err) {
      console.error("Erro ao salvar mensagem:", err);
    }

    io.to(socket.room).emit("message", { username, msg });
  });

  socket.on("disconnect", () => {
    if (socket.room) {
      io.to(socket.room).emit("message", { username: "Sistema", msg: `Usuário saiu da sala.` });
    }
    console.log("🔴 Socket desconectado:", socket.id);
  });
});

// ---------- Inicialização segura ----------
async function init() {
  try {
    await initDb();

    server.listen(PORT, "0.0.0.0", () => {
      console.log(`Servidor rodando em http://localhost:${PORT}`);
      const nets = os.networkInterfaces();
      Object.keys(nets).forEach((ifname) => {
        nets[ifname].forEach((net) => {
          if (net.family === 'IPv4' && !net.internal) {
            console.log(`➡️ Acesso LAN: http://${net.address}:${PORT}`);
          }
        });
      });
    });
  } catch (err) {
    console.error("ERRO AO INICIAR SERVIDOR:", err);
    process.exit(1);
  }
}

init();
