// Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

import "dotenv/config";
import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";

const app = express();
const db = new Database("data.db");

// --- DB setup ---
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  quantity INTEGER NOT NULL DEFAULT 0
);
`);

const hasProducts = db.prepare("SELECT COUNT(*) AS c FROM products").get().c > 0;
if (!hasProducts) {
  const seed = db.prepare("INSERT INTO products (name, quantity) VALUES (?, ?)");
  seed.run("Tinto Reserva", 12);
  seed.run("Branco Seco", 8);
  seed.run("Rosé Suave", 5);
}

app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "troque-este-segredo",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 }
  })
);

function page(title, body, opts = {}) {
  const { flash = "" } = opts;
  return `<!doctype html><html lang="pt-br"><head><meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${title}</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 2rem; background:#111; color:#eee; }
    a, button, input[type=submit] { cursor:pointer }
    .card { background:#1b1b1b; border:1px solid #333; padding:1rem; border-radius:12px; max-width:480px }
    .row { display:flex; gap:.5rem; align-items:center }
    .row > * { flex:1 }
    input, button, select { background:#111; color:#eee; border:1px solid #333; padding:.6rem .8rem; border-radius:8px }
    table { width:100%; border-collapse: collapse; margin-top:1rem }
    th, td { padding:.6rem; border-bottom:1px solid #2a2a2a; text-align:left }
    .actions { display:flex; gap:.4rem }
    .topbar { display:flex; align-items:center; justify-content:space-between; margin-bottom:1rem }
    .flash { margin: .5rem 0 1rem; color:#f0c; }
    .muted { color:#aaa; font-size:.9rem }
    .btn { background:#6d28d9; border:none }
    .btn.secondary { background:#2a2a2a; }
    .btn.danger { background:#7c2d12; }
    .grid { display:grid; grid-template-columns: 1fr; gap:1rem; }
    @media(min-width:700px){ .grid { grid-template-columns: 1fr 1fr; } .card { max-width:unset } }
    .center { max-width:480px; margin:auto; }

    label {
      display: block;
      margin-top: .5rem;
      margin-bottom: .25rem;
    }

    input[type="email"],
    input[type="password"] {
      display: block;
      width: 100%;
    }

  </style>
  </head><body>${flash ? `<div class="flash">${flash}</div>` : ""}${body}</body></html>`;
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

app.get("/", (req, res) => req.session.user ? res.redirect("/inventory") : res.redirect("/login"));

app.get("/register", (req, res) => {
  res.send(page("Cadastro - Vinheria", `
  <div class="center"><h1>Cadastro</h1>
  <div class="card"><form method="POST" action="/register">
  <label>Email</label><input name="email" type="email" required />
  <label>Senha</label><input name="password" type="password" minlength="4" required />
  <div style="margin-top:1rem" class="row">
  <input class="btn" type="submit" value="Criar conta" />
  <a class="btn secondary" href="/login" style="text-align:center; text-decoration:none; padding:.6rem .8rem">Login</a>
  </div></form></div><p class="muted" style="margin-top:1rem">cadastro → login → estoque</p></div>`));
});

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    db.prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)").run(email.trim().toLowerCase(), hash);
    req.session.flash = "Cadastro realizado. Faça login.";
    res.redirect("/login");
  } catch (e) {
    const msg = e.code === "SQLITE_CONSTRAINT_UNIQUE" ? "Email já cadastrado." : "Erro.";
    res.send(page("Cadastro - Vinheria", `<p>${msg}</p><a href="/register">Voltar</a>`));
  }
});

app.get("/login", (req, res) => {
  const flash = req.session.flash || "";
  req.session.flash = null;
  res.send(page("Login - Vinheria", `
  <div class="center"><h1>Login</h1>
  <div class="card"><form method="POST" action="/login">
  <label>Email</label><input name="email" type="email" required />
  <label>Senha</label><input name="password" type="password" required />
  <label>Token de acesso</label><input name="accessToken" type="password" required />
  <div style="margin-top:1rem" class="row">
  <input class="btn" type="submit" value="Entrar" />
  <a class="btn secondary" href="/register" style="text-align:center; text-decoration:none; padding:.6rem .8rem">Criar conta</a>
  </div></form></div></div>`, { flash }));
});

app.post("/login", async (req, res) => {
  const { email, password, accessToken } = req.body;

  const expectedToken = process.env.ACCESS_TOKEN;
  if (!expectedToken || accessToken !== expectedToken) {
    return res.send("Token de acesso inválido.");
  }

  const user = db
    .prepare("SELECT * FROM users WHERE email = ?")
    .get((email || "").trim().toLowerCase());

  if (!user) return res.send("Credenciais inválidas");

  const ok = await bcrypt.compare(password || "", user.password_hash);
  if (!ok) return res.send("Credenciais inválidas");

  req.session.user = { id: user.id, email: user.email };
  res.redirect("/inventory");
});


app.post("/logout", (req, res) => req.session.destroy(() => res.redirect("/login")));

app.get("/inventory", requireAuth, (req, res) => {
  const products = db.prepare("SELECT * FROM products ORDER BY id").all();
  const email = req.session.user.email;
  res.send(page("Estoque", `
  <div class="topbar">
    <h1>Estoque</h1>
    <form method="POST" action="/logout"><span class="muted">${email}</span>
    <button class="btn danger" type="submit">Sair</button></form>
  </div>
  <div class="grid">
    <div class="card">
      <h2>Produtos</h2>
      <table><thead><tr><th>ID</th><th>Nome</th><th>Qtd</th><th>Ações</th></tr></thead><tbody>
      ${products.map(p=>`
      <tr><td>${p.id}</td><td>${p.name}</td><td>${p.quantity}</td>
      <td class="actions">
      <form method="POST" action="/inventory/${p.id}/decr"><button class="btn secondary">-1</button></form>
      <form method="POST" action="/inventory/${p.id}/incr"><button class="btn">+1</button></form>
      <form method="POST" action="/inventory/${p.id}/delete"><button class="btn danger">Del</button></form>
      </td></tr>`).join("")}
      </tbody></table>
    </div>
    <div class="card">
      <h2>Adicionar Produto</h2>
      <form method="POST" action="/inventory/add">
        <label>Nome</label><input name="name" required />
        <label>Quantidade</label><input name="quantity" type="number" value="0" />
        <div style="margin-top:1rem"><input class="btn" type="submit" value="Adicionar" /></div>
      </form>
    </div>
  </div>`));
});

app.post("/inventory/add", requireAuth, (req, res) => {
  db.prepare("INSERT INTO products (name, quantity) VALUES (?, ?)").run(req.body.name.trim(), Number(req.body.quantity||0));
  res.redirect("/inventory");
});

app.post("/inventory/:id/incr", requireAuth, (req, res) => {
  db.prepare("UPDATE products SET quantity = quantity + 1 WHERE id = ?").run(req.params.id);
  res.redirect("/inventory");
});

app.post("/inventory/:id/decr", requireAuth, (req, res) => {
  db.prepare("UPDATE products SET quantity = MAX(quantity - 1, 0) WHERE id = ?").run(req.params.id);
  res.redirect("/inventory");
});

app.post("/inventory/:id/delete", requireAuth, (req, res) => {
  db.prepare("DELETE FROM products WHERE id = ?").run(req.params.id);
  res.redirect("/inventory");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Rodando em http://localhost:${PORT}`));
