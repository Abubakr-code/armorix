// Demo only: an intentionally vulnerable Express API used to showcase Armorix.
const express = require("express");
const mysql = require("mysql2");
const { exec } = require("child_process");
const path = require("path");
const jwt = require("jsonwebtoken");

const app = express();
const db = mysql.createConnection({ host: "localhost", user: "shop", password: "Sh0p!2026_prod#db" });

app.get("/api/users", (req, res) => {
  const id = req.query.id;
  const sql = "SELECT * FROM users WHERE id = " + id;
  db.query(sql, (err, rows) => res.json(rows));
});

app.get("/api/orders", (req, res) => {
  // Safe: bound parameter
  db.query("SELECT * FROM orders WHERE user_id = ?", [req.query.user], (err, rows) => res.json(rows));
});

app.post("/api/ping", (req, res) => {
  const host = req.body.host;
  exec(`ping -c 1 ${host}`, (err, out) => res.send(out));
});

app.post("/api/calc", (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});

app.get("/api/hello", (req, res) => {
  res.send("<h1>Hello, " + req.query.name + "</h1>");
});

app.get("/api/invoice", (req, res) => {
  res.sendFile(path.join(__dirname, "invoices", req.query.file));
});

app.post("/api/preview", async (req, res) => {
  const page = await fetch(req.body.url);
  res.send(await page.text());
});

app.post("/api/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email, password: req.body.password });
  res.json({ ok: !!user });
});

app.get("/api/me", (req, res) => {
  const claims = jwt.verify(req.cookies.token, SECRET, { algorithms: ["HS256", "none"] });
  res.json(claims);
});

app.listen(3000);
