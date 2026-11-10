"""Unit tests for the static engines: every case is a tiny piece of code with a known answer."""
from pathlib import Path

import pytest

from sca.engines import external, python_ast, rules_engine, secrets
from sca.walker import SourceFile, detect_language, walk_project


def make(code: str, name: str) -> SourceFile:
    return SourceFile(Path(name), name, detect_language(Path(name)), code)


def cwes(findings):
    return sorted({f.cwe for f in findings})


# ------------------------------------------------------------------ Python AST engine
PY_VULNERABLE = [
    ("CWE-89", 'import sqlite3\nfrom flask import request\ndef f(cur):\n    uid = request.args["id"]\n    cur.execute("SELECT * FROM t WHERE id = " + uid)\n'),
    ("CWE-89", 'def f(cur, name):\n    q = f"SELECT * FROM t WHERE n = \'{name}\'"\n    cur.execute(q)\n'),
    ("CWE-89", 'def f(cur, name):\n    cur.execute("SELECT * FROM t WHERE n = %s" % name)\n'),
    ("CWE-78", 'import os\ndef f(host):\n    os.system("ping " + host)\n'),
    ("CWE-78", 'import subprocess as sp\ndef f(x):\n    sp.run("ls " + x, shell=True)\n'),
    ("CWE-95", 'def f():\n    data = input()\n    return eval(data)\n'),
    ("CWE-502", 'import pickle\ndef f(blob):\n    return pickle.loads(blob)\n'),
    ("CWE-502", 'import yaml\ndef f(text):\n    return yaml.load(text)\n'),
    ("CWE-327", 'import hashlib\ndef f(password):\n    return hashlib.md5(password).hexdigest()\n'),
    ("CWE-338", 'import random\ndef f():\n    token = random.randint(0, 9999)\n    return token\n'),
    ("CWE-295", 'import requests\ndef f(u):\n    return requests.get(u, verify=False)\n'),
    ("CWE-489", 'def f(app):\n    app.run(debug=True)\n'),
    ("CWE-377", 'import tempfile\nname = tempfile.mktemp()\n'),
    ("CWE-732", 'import os\nos.chmod("/tmp/x", 0o777)\n'),
    ("CWE-347", 'import jwt\ndef f(t):\n    return jwt.decode(t, options={"verify_signature": False})\n'),
    ("CWE-22", 'from flask import request\ndef f():\n    return open("/srv/" + request.args["p"]).read()\n'),
    ("CWE-918", 'import requests\nfrom flask import request\ndef f():\n    return requests.get(request.args["u"])\n'),
    ("CWE-601", 'from flask import request, redirect\ndef f():\n    return redirect(request.args.get("next"))\n'),
    ("CWE-79", 'from flask import request\ndef f():\n    n = request.args.get("n")\n    return "<b>" + n + "</b>"\n'),
    ("CWE-1336", 'from flask import request, render_template_string\ndef f():\n    return render_template_string("<p>" + request.args["x"] + "</p>")\n'),
]

PY_SAFE = [
    'def f(cur, uid):\n    cur.execute("SELECT * FROM t WHERE id = ?", (uid,))\n',
    'import subprocess\ndef f(host):\n    subprocess.run(["ping", "-c", "1", host])\n',
    'import os\nos.system("clear")\n',
    'import ast\ndef f(text):\n    return ast.literal_eval(text)\n',
    'import yaml\ndef f(text):\n    return yaml.load(text, Loader=yaml.SafeLoader)\n',
    'import yaml\ndef f(text):\n    return yaml.safe_load(text)\n',
    'import hashlib\ndef f(data):\n    return hashlib.sha256(data).hexdigest()\n',
    'import hashlib\ndef f(data):\n    return hashlib.md5(data, usedforsecurity=False).hexdigest()\n',
    'import random\ndef f(items):\n    return random.choice(items)\n',
    'import secrets\ndef f():\n    token = secrets.token_hex(16)\n    return token\n',
    'def f(app):\n    app.run(debug=False)\n',
    'from flask import request\ndef f():\n    n = int(request.args["n"])\n    return open("/srv/page%d.txt" % n).read()\n',
    'from flask import request\nfrom werkzeug.utils import secure_filename\ndef f():\n    return open("/srv/" + secure_filename(request.args["p"])).read()\n',
    '# eval(user_input) in a comment is not code\nx = 1\n',
]


@pytest.mark.parametrize("cwe,code", PY_VULNERABLE)
def test_python_ast_detects(cwe, code):
    assert cwe in cwes(python_ast.scan_file(make(code, "a.py")))


@pytest.mark.parametrize("code", PY_SAFE)
def test_python_ast_ignores_safe_code(code):
    assert python_ast.scan_file(make(code, "a.py")) == []


def test_python_ast_marks_taint_and_raises_confidence():
    tainted = 'from flask import request\ndef f(cur):\n    cur.execute("SELECT " + request.args["c"])\n'
    unknown = 'def f(cur, c):\n    cur.execute("SELECT " + c)\n'
    a = python_ast.scan_file(make(tainted, "a.py"))[0]
    b = python_ast.scan_file(make(unknown, "a.py"))[0]
    assert a.tainted and not b.tainted
    assert a.confidence > b.confidence


def test_python_ast_route_parameters_are_sources():
    code = ('import os\n@app.route("/x/<name>")\ndef handler(name):\n'
            '    os.system("echo " + name)\n')
    finding = python_ast.scan_file(make(code, "a.py"))[0]
    assert finding.cwe == "CWE-78" and finding.tainted


def test_python_ast_survives_invalid_python():
    assert python_ast.scan_file(make("def broken(:\n", "a.py")) == []


# ------------------------------------------------------------------ pattern rules
RULE_VULNERABLE = [
    ("a.js", "CWE-89", 'db.query("SELECT * FROM u WHERE n = \'" + name + "\'");'),
    ("a.js", "CWE-89", "db.query(`SELECT * FROM u WHERE id = ${id}`);"),
    ("a.js", "CWE-78", 'exec("ls " + dir, cb);'),
    ("a.js", "CWE-95", "const r = eval(input);"),
    ("a.js", "CWE-79", "el.innerHTML = userText;"),
    ("a.js", "CWE-79", 'res.send("<p>" + req.query.q + "</p>");'),
    ("a.js", "CWE-22", "fs.readFile(req.query.file, cb);"),
    ("a.js", "CWE-601", "res.redirect(req.query.next);"),
    ("a.js", "CWE-327", 'crypto.createHash("md5");'),
    ("a.js", "CWE-338", "const token = Math.random().toString(36);"),
    ("a.js", "CWE-295", "const agent = new https.Agent({ rejectUnauthorized: false });"),
    ("a.ts", "CWE-943", "const user = await Users.findOne(req.body);"),
    ("a.php", "CWE-89", '$r = mysqli_query($c, "SELECT * FROM t WHERE id=" . $_GET["id"]);'),
    ("a.php", "CWE-78", '$o = shell_exec("ping " . $host);'),
    ("a.php", "CWE-79", 'echo $_GET["q"];'),
    ("a.php", "CWE-98", 'include($_GET["page"]);'),
    ("a.php", "CWE-502", '$o = unserialize($data);'),
    ("A.java", "CWE-89", 'rs = st.executeQuery("SELECT * FROM t WHERE id=" + id);'),
    ("A.java", "CWE-78", 'Runtime.getRuntime().exec("ping " + host);'),
    ("A.java", "CWE-327", 'MessageDigest md = MessageDigest.getInstance("MD5");'),
    ("A.java", "CWE-327", 'Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");'),
    ("A.java", "CWE-502", "ObjectInputStream in = new ObjectInputStream(stream);"),
    ("a.c", "CWE-242", "gets(buf);"),
    ("a.c", "CWE-120", "strcpy(dst, src);"),
    ("a.c", "CWE-120", 'sprintf(buf, "%s", s);'),
    ("a.c", "CWE-134", "printf(user);"),
    ("a.cpp", "CWE-78", "system(cmd);"),
    ("a.go", "CWE-295", "cfg := &tls.Config{InsecureSkipVerify: true}"),
    ("a.go", "CWE-89", 'rows, _ := db.Query("SELECT * FROM t WHERE id=" + id)'),
    ("a.cs", "CWE-89", 'var cmd = new SqlCommand("SELECT * FROM t WHERE id=" + id, conn);'),
]

RULE_SAFE = [
    ("a.js", 'db.query("SELECT * FROM u WHERE n = ?", [name]);'),
    ("a.js", 'el.innerHTML = "<b>static</b>";'),
    ("a.js", "el.textContent = userText;"),
    ("a.js", "// const r = eval(input);"),
    ("a.js", "const i = Math.floor(Math.random() * 10);"),
    ("a.js", 'crypto.createHash("sha256");'),
    ("a.js", "const m = /a+/.exec(text + suffix);"),
    ("a.php", 'echo htmlspecialchars($_GET["q"]);'),
    ("a.php", '$o = shell_exec("ping " . escapeshellarg($host));'),
    ("a.php", '$s = $pdo->prepare("SELECT * FROM t WHERE id = ?");'),
    ("A.java", 'PreparedStatement ps = c.prepareStatement("SELECT * FROM t WHERE id = ?");'),
    ("A.java", 'MessageDigest md = MessageDigest.getInstance("SHA-256");'),
    ("a.c", "fgets(buf, sizeof(buf), stdin);"),
    ("a.c", 'printf("%s", user);'),
    ("a.c", 'snprintf(buf, sizeof(buf), "%s", s);'),
    ("a.c", 'strcpy(dst, "constant");'),
    ("a.c", '/* gets(buf); */'),
]


@pytest.mark.parametrize("name,cwe,code", RULE_VULNERABLE)
def test_rules_detect(name, cwe, code):
    assert cwe in cwes(rules_engine.scan_file(make(code + "\n", name)))


@pytest.mark.parametrize("name,code", RULE_SAFE)
def test_rules_ignore_safe_code(name, code):
    assert rules_engine.scan_file(make(code + "\n", name)) == []


def test_rules_have_unique_ids_and_valid_fields():
    rules = rules_engine.load_rules()
    assert len(rules) >= 60
    assert len({r.id for r in rules}) == len(rules)
    for rule in rules:
        assert rule.cwe.startswith("CWE-")
        assert rule.severity in ("critical", "high", "medium", "low", "info")
        assert 0 < rule.confidence <= 1


def test_block_comments_are_skipped():
    code = "/*\n gets(buf);\n strcpy(a, b);\n*/\nint x;\n"
    assert rules_engine.scan_file(make(code, "a.c")) == []


# ------------------------------------------------------------------ secrets
# the fake secrets are assembled at run time so that this file contains none itself
FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_GITHUB = "ghp_" + "a1B2c3D4e5F6g7H8i9J0" * 2
FAKE_KEY = "9f8e7d6c5b4a3928" + "1706f5e4d3c2b1a0"

SECRET_LINES = [
    'aws_key = "%s"' % FAKE_AWS,
    'GITHUB = "%s"' % FAKE_GITHUB,
    'db_password = "Sup3r-S3cret!"',
    'const apiKey = "%s";' % FAKE_KEY,
    "password: 'hunter2hunter2'",
    "url = 'postgres://admin:Tr1ckyPass99@db.local:5432/app'",
    "-----BEGIN RSA PRIVATE KEY-----",
]
NOT_SECRET_LINES = [
    'password = os.environ["DB_PASSWORD"]',
    'password = ""',
    'password = "changeme"',
    'api_key = "${API_KEY}"',
    'token_url = "https://example.com/oauth/token"',
    'password_label = "Enter your password"',
    'api_key = "your-api-key-here"',
    'secret_name = "prod/db/main-credentials"',
    'url = "postgres://user:${DB_PASS}@db.local/app"',
]


@pytest.mark.parametrize("line", SECRET_LINES)
def test_secrets_detected(line):
    assert secrets.scan_file(make(line + "\n", "conf.py"))


@pytest.mark.parametrize("line", NOT_SECRET_LINES)
def test_secrets_ignore_placeholders(line):
    assert secrets.scan_file(make(line + "\n", "conf.py")) == []


def test_secret_value_is_masked_in_output():
    finding = secrets.scan_file(make('db_password = "Sup3r-S3cret!"\n', "conf.py"))[0]
    assert "Sup3r-S3cret!" not in finding.snippet
    assert "Sup3r-S3cret!" not in finding.context
    assert "*" in finding.snippet


def test_entropy_orders_random_above_words():
    assert secrets.shannon_entropy(FAKE_KEY) > secrets.shannon_entropy("aaaaaaaaaaaaaaaa")


# ------------------------------------------------------------------ external adapters
def test_parse_bandit(tmp_path):
    (tmp_path / "x.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    data = {"results": [{"filename": str(tmp_path / "x.py"), "line_number": 2,
                         "issue_text": "Starting a process with a shell", "test_id": "B605",
                         "issue_severity": "HIGH", "issue_confidence": "HIGH",
                         "issue_cwe": {"id": 78}, "line_range": [2]}]}
    finding = external.parse_bandit(data, tmp_path)[0]
    assert (finding.file, finding.line, finding.cwe, finding.severity) == \
        ("x.py", 2, "CWE-78", "high")
    assert finding.snippet == "os.system(cmd)" and finding.engines == ["bandit"]


def test_parse_semgrep(tmp_path):
    (tmp_path / "a.js").write_text("eval(x)\n", encoding="utf-8")
    data = {"results": [{"check_id": "javascript.lang.security.eval-detected",
                         "path": str(tmp_path / "a.js"), "start": {"line": 1},
                         "end": {"line": 1},
                         "extra": {"message": "eval detected", "severity": "ERROR",
                                   "metadata": {"cwe": ["CWE-95: Eval Injection"],
                                                "confidence": "HIGH"}}}]}
    finding = external.parse_semgrep(data, tmp_path)[0]
    assert (finding.file, finding.cwe, finding.severity, finding.confidence) == \
        ("a.js", "CWE-95", "high", 0.8)


def test_parse_gitleaks_masks_secret(tmp_path):
    data = [{"Description": "Generic API Key", "File": str(tmp_path / "c.env"),
             "StartLine": 3, "RuleID": "generic-api-key", "Secret": FAKE_KEY,
             "Match": "KEY=" + FAKE_KEY}]
    finding = external.parse_gitleaks(data, tmp_path)[0]
    assert finding.cwe == "CWE-798" and finding.line == 3
    assert FAKE_KEY not in finding.snippet


@pytest.mark.skipif(not external.bandit_available(), reason="bandit not installed")
def test_run_bandit_end_to_end(tmp_path):
    (tmp_path / "x.py").write_text("import pickle\n\ndef f(b):\n    return pickle.loads(b)\n",
                                   encoding="utf-8")
    findings, note = external.run_bandit(tmp_path)
    assert note.startswith("ok")
    assert any(f.cwe == "CWE-502" and f.line == 4 for f in findings)


# ------------------------------------------------------------------ walker
def test_walker_skips_dependencies_and_binaries(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text("eval(x)\n", encoding="utf-8")
    (tmp_path / "logo.py").write_bytes(b"\x00\x01\x02binary")
    (tmp_path / "bundle.min.js").write_text("eval(x)\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("hello\n", encoding="utf-8")
    assert [f.rel for f in walk_project(str(tmp_path))] == ["src/a.py"]
