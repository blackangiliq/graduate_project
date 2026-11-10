// Safe counterpart of samples/vulnerable_app/server.js. Every finding here is a false positive.
const express = require("express");
const { execFile } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const mysql = require("mysql");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const db = mysql.createConnection({
  host: "localhost",
  user: "shop",
  password: process.env.DB_PASSWORD,
  database: "shop",
});
const JWT_SECRET = process.env.JWT_SECRET;
const passwordPlaceholder = "Type your password";

app.get("/users", (req, res) => {
  db.query("SELECT * FROM users WHERE name = ?", [req.query.name], (err, rows) => res.json(rows));
});

app.get("/dns", (req, res) => {
  execFile("nslookup", [String(req.query.host)], (err, out) => res.json({ out }));
});

app.get("/greet", (req, res) => {
  res.json({ message: "Welcome", name: req.query.name });
});

app.get("/file", (req, res) => {
  const name = path.basename(String(req.query.path));
  fs.readFile(path.join(__dirname, "public", name), (err, data) => res.end(data));
});

app.get("/out", (req, res) => {
  res.redirect("/home");
});

app.post("/calc", (req, res) => {
  // no eval(): only numbers are accepted
  const result = Number(req.body.a) + Number(req.body.b);
  res.json({ result });
});

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

function resetToken() {
  const token = crypto.randomBytes(32).toString("hex");
  return token;
}

function verify(token) {
  return jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
}

function showName(name) {
  document.getElementById("name").textContent = name;
  document.getElementById("footer").innerHTML = "<small>Shop demo</small>";
}

function matchVersion(text) {
  return /v(\d+)/.exec(text + "");
}

app.listen(3000);
module.exports = { hashPassword, resetToken, verify, showName, matchVersion, passwordPlaceholder };
