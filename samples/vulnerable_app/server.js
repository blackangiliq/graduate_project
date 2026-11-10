// Deliberately vulnerable Express server. FOR TESTING THE ANALYZER ONLY.
const express = require("express");
const { exec } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const mysql = require("mysql");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const db = mysql.createConnection({ host: "localhost", user: "root", password: "r00t-Adm1n-pw", database: "shop" }); // [J01]
const JWT_SECRET = "c2VjcmV0LWtleS1mb3ItandzLTIwMjQ"; // [J02]

app.get("/users", (req, res) => {
  db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'", (err, rows) => res.json(rows)); // [J03]
});

app.get("/orders", (req, res) => {
  db.query(`SELECT * FROM orders WHERE id = ${req.query.id}`, (err, rows) => res.json(rows)); // [J04]
});

app.get("/products", (req, res) => {
  db.query("SELECT * FROM products WHERE id = ?", [req.query.id], (err, rows) => res.json(rows)); // [J05]
});

app.get("/dns", (req, res) => {
  exec("nslookup " + req.query.host, (err, out) => res.json({ out })); // [J06]
});

app.get("/greet", (req, res) => {
  res.send("<h1>Welcome " + req.query.name + "</h1>"); // [J07]
});

app.get("/file", (req, res) => {
  fs.readFile("./public/" + req.query.path, (err, data) => res.end(data)); // [J08]
});

app.get("/out", (req, res) => {
  res.redirect(req.query.url); // [J09]
});

app.post("/calc", (req, res) => {
  const result = eval(req.body.formula); // [J10]
  res.json({ result });
});

function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex"); // [J11]
}

function resetToken() {
  const token = Math.random().toString(36).slice(2); // [J12]
  return token;
}

function verify(token) {
  return jwt.verify(token, JWT_SECRET, { algorithms: ["HS256", "none"] }); // [J13]
}

function checksum(data) {
  return crypto.createHash("sha256").update(data).digest("hex"); // [J14]
}

function shuffleIndex(n) {
  return Math.floor(Math.random() * n); // [J15]
}

function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object") {
      target[key] = merge(target[key] || {}, source[key]); // [J16]
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.post("/settings", (req, res) => {
  res.json(merge({}, req.body));
});

app.listen(3000);
module.exports = { hashPassword, resetToken, verify, checksum, shuffleIndex };
