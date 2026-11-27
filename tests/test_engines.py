"""Unit tests for the static engines: every case is a tiny piece of code with a known answer."""
from pathlib import Path

import pytest

from sca.engines import external, python_ast, rules_engine, secrets, taint_lite
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


def test_python_ast_follows_user_input_into_a_helper_function():
    code = ('from flask import request\n'
            'def read_template(name):\n'
            '    return open("templates/" + name).read()\n'
            'def view():\n'
            '    return read_template(request.args.get("tpl"))\n')
    findings = python_ast.scan_file(make(code, "a.py"))
    assert [(f.cwe, f.line, f.tainted) for f in findings] == [("CWE-22", 3, True)]
    assert "line 5" in findings[0].description


def test_python_ast_interprocedural_keyword_argument_and_method():
    code = ('import os\n'
            'class Jobs:\n'
            '    def run(self, command):\n'
            '        os.system("nice " + command)\n'
            '    def handle(self, request):\n'
            '        self.run(command=request.args["c"])\n')
    findings = python_ast.scan_file(make(code, "a.py"))
    assert len(findings) == 1 and findings[0].tainted and findings[0].confidence >= 0.8


def test_python_ast_interprocedural_respects_sanitizers_and_constants():
    sanitized = ('from flask import request\n'
                 'from werkzeug.utils import secure_filename\n'
                 'def read_template(name):\n'
                 '    return open("templates/" + secure_filename(name)).read()\n'
                 'def view():\n'
                 '    return read_template(request.args.get("tpl"))\n')
    constant = ('def read_template(name):\n'
                '    return open("templates/" + name).read()\n'
                'def view():\n'
                '    return read_template("home.html")\n')
    assert python_ast.scan_file(make(sanitized, "a.py")) == []
    assert python_ast.scan_file(make(constant, "a.py")) == []


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
    ("a.cs", "CWE-295", "handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;"),
    ("a.cs", "CWE-338", "var token = new Random().Next().ToString();"),
    ("a.cs", "CWE-79", "@Html.Raw(Model.Comment)"),
    ("a.cs", "CWE-22", 'var text = File.ReadAllText("docs/" + Request.Query["name"]);'),
    ("a.go", "CWE-78", 'cmd := exec.Command("sh", "-c", "ping " + host)'),
    ("a.go", "CWE-338", "token := rand.Intn(999999)"),
    ("a.go", "CWE-79", "page := template.HTML(comment)"),
    ("a.go", "CWE-22", 'data, _ := os.ReadFile("files/" + r.FormValue("name"))'),
    ("a.rb", "CWE-89", 'User.where("name = \'#{params[:name]}\'")'),
    ("a.rb", "CWE-89", 'User.where("name = \'" + name + "\'")'),
    ("a.rb", "CWE-78", 'system("ping -c 1 #{host}")'),
    ("a.rb", "CWE-78", "out = `ls #{dir}`"),
    ("a.rb", "CWE-95", "eval(params[:code])"),
    ("a.rb", "CWE-502", "obj = Marshal.load(data)"),
    ("a.rb", "CWE-22", "send_file params[:path]"),
    ("a.rb", "CWE-601", "redirect_to params[:next]"),
    ("a.rb", "CWE-79", "raw params[:comment]"),
    ("a.rb", "CWE-327", "Digest::MD5.hexdigest(password)"),
    ("a.rb", "CWE-295", "http.verify_mode = OpenSSL::SSL::VERIFY_NONE"),
    ("a.rb", "CWE-338", "reset_token = rand(999999).to_s"),
    ("a.sh", "CWE-95", 'eval "$USER_COMMAND"'),
    ("a.sh", "CWE-494", "curl -s https://example.com/install.sh | sudo bash"),
    ("a.sh", "CWE-295", "curl -k https://internal.example.com/data"),
    ("a.sh", "CWE-732", "chmod -R 777 /var/www"),
    ("a.ps1", "CWE-95", "Invoke-Expression $userInput"),
    ("a.ps1", "CWE-295", "Invoke-WebRequest $url -SkipCertificateCheck"),
    ("a.ps1", "CWE-798", '$p = ConvertTo-SecureString "Winter2024!" -AsPlainText -Force'),
    ("a.rs", "CWE-295", "let c = Client::builder().danger_accept_invalid_certs(true).build()?;"),
    ("a.rs", "CWE-89", 'let rows = sqlx::query(&format!("SELECT * FROM t WHERE id = {}", id))'),
    ("a.rs", "CWE-78", 'let out = Command::new("sh").arg("-c").arg(cmd).output()?;'),
    ("a.kt", "CWE-89", 'val rs = st.executeQuery("SELECT * FROM t WHERE id=" + id)'),
    ("a.kt", "CWE-327", 'val md = MessageDigest.getInstance("MD5")'),
    ("a.scala", "CWE-78", 'Runtime.getRuntime().exec("ping " + host)'),
    ("a.vue", "CWE-79", "el.innerHTML = userText;"),
    ("a.dart", "CWE-295", "client.badCertificateCallback = (cert, host, port) => true;"),
    ("a.dart", "CWE-319", "final r = await http.get(Uri.parse('http://api.shop-backend.io/v1/login'));"),
    ("a.dart", "CWE-89", "final rows = await db.rawQuery(\"SELECT * FROM users WHERE email = '$email'\");"),
    ("a.dart", "CWE-89", "await db.query('users', where: 'id = $id');"),
    ("a.dart", "CWE-312", "await prefs.setString('auth_token', token);"),
    ("a.dart", "CWE-328", "final digest = md5.convert(utf8.encode(password));"),
    ("a.dart", "CWE-327", "final encrypter = Encrypter(AES(key, mode: AESMode.ecb));"),
    ("a.dart", "CWE-321", "final key = Key.fromUtf8('my32lengthsupersecretnooneknows1');"),
    ("a.dart", "CWE-1204", "final iv = IV.fromLength(16);"),
    ("a.dart", "CWE-532", "debugPrint('User token: $token');"),
    ("a.dart", "CWE-200", "          allowUniversalAccessFromFileURLs: true,"),
    ("a.dart", "CWE-489", "AndroidWebViewController.enableDebugging(true);"),
    ("a.dart", "CWE-78", "final r = await Process.run('sh', ['-c', 'tar -xzf $archive']);"),
    ("a.dart", "CWE-78", "await Process.run(command, []);"),
    ("a.dart", "CWE-732", "Context.getSharedPreferences(token, MODE_WORLD_READABLE);"),
    ("a.dart", "CWE-338", "final gen = Random(12345); final bytes = Uint8List(16);"),
    ("a.dart", "CWE-470", "final m = reflector.reflect(obj); m.invoke(name, []);"),
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
    ("a.cs", '@Html.Raw("<b>static</b>")'),
    ("a.cs", "var index = new Random().Next(10);"),
    ("a.cs", 'var text = File.ReadAllText("docs/" + Path.GetFileName(Request.Query["name"]));'),
    ("a.go", 'cmd := exec.Command("ping", "-c", "1", host)'),
    ("a.go", "index := rand.Intn(len(items))"),
    ("a.go", 'page := template.HTML("<b>static</b>")'),
    ("a.rb", 'User.where("name = ?", params[:name])'),
    ("a.rb", "User.where(name: params[:name])"),
    ("a.rb", 'system("ping", "-c", "1", host)'),
    ("a.rb", "data = YAML.safe_load(text)"),
    ("a.rb", "send_file File.basename(params[:path])"),
    ("a.rb", "redirect_to root_path"),
    ("a.rb", "Digest::SHA256.hexdigest(data)"),
    ("a.rb", "index = rand(items.size)"),
    ("a.rb", "# eval(params[:code])"),
    ("a.sh", "curl -fsSL https://example.com/file.tar.gz -o file.tar.gz"),
    ("a.sh", "chmod 640 config.ini"),
    ("a.sh", "# eval $cmd"),
    ("a.ps1", "Invoke-WebRequest $url -OutFile out.zip"),
    ("a.ps1", "$p = Read-Host -AsSecureString"),
    ("a.rs", 'let rows = sqlx::query("SELECT * FROM t WHERE id = ?").bind(id)'),
    ("a.rs", 'let out = Command::new("ls").arg(dir).output()?;'),
    ("a.kt", 'val md = MessageDigest.getInstance("SHA-256")'),
    ("a.dart", "client.badCertificateCallback = (cert, host, port) => false;"),
    ("a.dart", "final r = await http.get(Uri.parse('https://api.shop-backend.io/v1/login'));"),
    ("a.dart", "final rows = await db.rawQuery('SELECT * FROM $table WHERE $columnId = ?', [id]);"),
    ("a.dart", "await prefs.setString('theme_mode', 'dark');"),
    ("a.dart", "final digest = sha256.convert(bytes);"),
    ("a.dart", "final iv = IV.fromSecureRandom(16);"),
    ("a.dart", "if (kDebugMode) debugPrint('token refreshed: $token');"),
    ("a.dart", "// client.badCertificateCallback = (cert, host, port) => true;"),
    ("a.dart", "final rng = Random.secure();"),
    ("a.dart", "await prefs.setString('fcm_token', fcmToken);"),
    ("a.dart", "await db.rawQuery('SELECT * FROM \"$tableName\" WHERE id = ?', [id]);"),
    ("a.dart", "print('Token expired: $isTokenExpired');"),
    ("a.dart", "final r = await Process.run('git', ['status']);"),
]


@pytest.mark.parametrize("name,cwe,code", RULE_VULNERABLE)
def test_rules_detect(name, cwe, code):
    assert cwe in cwes(rules_engine.scan_file(make(code + "\n", name)))


@pytest.mark.parametrize("name,code", RULE_SAFE)
def test_rules_ignore_safe_code(name, code):
    assert rules_engine.scan_file(make(code + "\n", name)) == []


def test_rules_have_unique_ids_and_valid_fields():
    rules = rules_engine.load_rules()
    assert len(rules) >= 95
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
]
NOT_SECRET_LINES = [
    "-----BEGIN RSA PRIVATE KEY-----",
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


# ------------------------------------------------------------------ taint-lite
def _traced(code: str, name: str, line: int) -> bool:
    return taint_lite.is_traced(make(code, name), line)


def test_taint_lite_traces_assignments_from_request_data():
    php = "<?php\n$name = $_POST['name'];\n$sql = \"SELECT * FROM u WHERE n = '$name'\";\n"
    java = ('String user = request.getParameter("user");\n'
            'String q = "SELECT * FROM u WHERE n = \'" + user + "\'";\n'
            'rs = st.executeQuery(q);\n')
    js = ("const params = new URLSearchParams(window.location.search);\n"
          "const message = params.get('msg');\n"
          "el.innerHTML = message;\n")
    destructured = "const { id } = req.query;\ndb.query(`SELECT * FROM t WHERE id = ${id}`);\n"
    go = 'name := r.FormValue("name")\nrows, _ := db.Query("SELECT * FROM t WHERE n=" + name)\n'
    assert _traced(php, "a.php", 3)
    assert _traced(java, "A.java", 3)          # two hops: user -> q -> executeQuery(q)
    assert _traced(js, "a.js", 3)
    assert _traced(destructured, "a.js", 2)
    assert _traced(go, "a.go", 2)
    assert _traced("echo $_GET['q'];\n", "a.php", 1)   # the source is on the line itself


def test_taint_lite_does_not_trace_constants_sanitized_values_or_table_lookups():
    constant = "<?php\n$name = 'admin';\n$sql = \"SELECT * FROM u WHERE n = '$name'\";\n"
    sanitized = "<?php\n$id = intval($_GET['id']);\n$sql = \"SELECT * FROM u WHERE id = $id\";\n"
    lookup = "<?php\n$page = $pages[$_GET['page']] ?? $pages['home'];\ninclude $page;\n"
    reassigned = ("let name = req.query.name;\nname = encodeURIComponent(name);\n"
                  "el.innerHTML = name;\n")
    parameter = "void copy(const char *input) {\n    strcpy(buffer, input);\n}\n"
    assert not _traced(constant, "a.php", 3)
    assert not _traced(sanitized, "a.php", 3)
    assert not _traced(lookup, "a.php", 3)
    assert not _traced(reassigned, "a.js", 3)
    assert not _traced(parameter, "a.c", 2)


def test_taint_lite_raises_confidence_only_for_injection_findings():
    php = "<?php\n$name = $_POST['name'];\n$sql = \"SELECT * FROM u WHERE n = '$name'\";\n$h = md5($name);\n"
    sf = make(php, "a.php")
    findings = rules_engine.scan_file(sf)
    before = {f.cwe: f.confidence for f in findings}
    assert taint_lite.apply(findings, {"a.php": sf}) == 1
    after = {f.cwe: (f.confidence, f.tainted) for f in findings}
    assert after["CWE-89"] == (pytest.approx(before["CWE-89"] + 0.15), True)
    assert after["CWE-327"] == (before["CWE-327"], False)


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


def test_walker_knows_many_languages():
    expected = {"a.rb": "ruby", "a.kt": "kotlin", "a.rs": "rust", "a.swift": "swift",
                "a.ps1": "powershell", "a.dart": "dart", "a.vue": "javascript",
                "a.scala": "scala", "a.lua": "lua", "a.sql": "sql", "a.tsx": "typescript"}
    for name, language in expected.items():
        assert detect_language(Path(name)) == language
    assert make("x", "a.kt").rule_language == "java"       # Kotlin shares the JVM API rules


@pytest.mark.parametrize("name,language", [
    ("view.jsp", "java"), ("part.jspf", "java"), ("list.ejs", "javascript"),
    ("Default.aspx", "csharp"), ("Site.master", "csharp"), ("Page.cshtml", "csharp"),
    ("Web.config", "config"), ("config/config.inc.php.dist", "php"),
    ("backup/config.properties.bak", "config"), ("notes.bak", None)])
def test_server_pages_templates_and_backup_copies_are_scanned(name, language):
    assert detect_language(Path(name)) == language


def test_django_tests_py_is_test_code():
    from sca.walker import is_test_path
    assert is_test_path("challenge/tests.py") and is_test_path("app/test.py")
    assert not is_test_path("app/contest.py")
    assert is_test_path("src/test/java/FooTest.java") and is_test_path("src/it/java/Reg.java")
    assert not is_test_path("src/main/java/Contest.java")


@pytest.mark.parametrize("name,scanned", [
    ("jquery-3.6.0.js", False), ("chart.js", False), ("wysihtml5-0.3.0.js", False),
    ("chartUtils.js", True), ("requireAuth.js", True), ("app.js", True)])
def test_vendored_javascript_libraries_are_skipped(name, scanned):
    assert (detect_language(Path(name)) is not None) == scanned


def test_spring_request_parameters_are_user_input():
    code = ('public Result f(@RequestParam String query) {\n'
            '  ResultSet r = statement.executeQuery(query);\n')
    assert taint_lite.is_traced(make(code, "Lesson.java"), 2)


def test_a_page_gets_the_javascript_rules_only_inside_its_scripts():
    page = ('<p>This lesson explains the Python <code>eval()</code> function.</p>\n'
            '<script>\n'
            '  out.innerHTML = location.hash;\n'
            '  toggle.innerHTML = dark ? "sun" : "moon";\n'
            '  document.write("<option value=\'English\'>English</option>");\n'
            '</script>\n'
            '<button onclick="eval(code)">run</button>\n')
    found = {(f.line, f.cwe) for f in rules_engine.scan_file(make(page, "lesson.html"))}
    assert found == {(3, "CWE-79"), (7, "CWE-95")}         # not the text of line 1
    assert make(page, "lesson.php").rule_languages == ("php", "javascript")
    assert make("x", "app.js").rule_languages == ("javascript",)


# ------------------------------------------------------------------ rules added after testing real projects
@pytest.mark.parametrize("cwe,code,name", [
    ("CWE-89", 'q := fmt.Sprintf(`SELECT * FROM users\n\twhere id=%s`, uid)\n', "a.go"),
    ("CWE-1004", 'c := http.Cookie{Name: "s", HttpOnly: false}\n', "a.go"),
    ("CWE-942", 'w.Header().Set("Access-Control-Allow-Origin", "*")\n', "a.go"),
    ("CWE-915", "user.update(params.require(:user).permit!)\n", "a.rb"),
    ("CWE-470", "model = params[:class].classify.constantize\n", "a.rb"),
    ("CWE-79", "<style>body { font-size:<%= raw cookies[:font] %> }</style>\n", "a.html.erb"),
    ("CWE-1004", "config.session_store :cookie_store, key: '_s', httponly: false\n", "a.rb"),
    ("CWE-79", "$html .= '<pre>Hello ' . $_GET['name'] . '</pre>';\n", "a.php"),
    ("CWE-434", "$p .= basename($_FILES['f']['name']);\nmove_uploaded_file($_FILES['f']['tmp_name'], $p);\n", "a.php"),
    ("CWE-611", "libxmljs.parseXmlString(xml, {noent: true})\n", "a.js"),
    ("CWE-95", "var out = mathjs.eval(req.body.eqn)\n", "a.js"),
    ("CWE-79", "<p><%- output.searchTerm %></p>\n", "a.ejs"),
    ("CWE-79", '<p><%= request.getParameter("q") %></p>\n', "a.jsp"),
    ("CWE-79", '<h1><%= Request["productNumber"] %></h1>\n', "a.aspx"),
    ("CWE-89", 'var a = new SQLiteDataAdapter("SELECT * FROM t WHERE id = " + id, conn);\n', "a.cs"),
    ("CWE-489", '<compilation debug="true" targetFramework="4.0">\n', "Web.config"),
    ("CWE-1004", '<httpCookies httpOnlyCookies="false" />\n', "Web.config"),
    ("CWE-79", "<p>{{ query|safe }}</p>\n", "a.html"),
    ("CWE-943", "return db.find({ $where: `this.orderId === '${id}'` })\n", "a.js"),
    ("CWE-611", "libxml2.ParseOption.XML_PARSE_NOENT | libxml2.ParseOption.XML_PARSE_DTDLOAD\n",
     "a.ts"),
    ("CWE-79", "swig.setDefaults({ autoescape: false })\n", "a.js"),
    ("CWE-79", "this.v = this.sanitizer.bypassSecurityTrustHtml(queryParam)\n", "a.ts"),
    ("CWE-95", "vm.runInContext('safeEval(orderLinesData)', sandbox)\n", "a.ts"),
    ("CWE-1333", "const regexPattern = /([0-9]+)+\\#/;\n", "a.js"),
])
def test_new_rules_find_what_the_real_projects_showed(cwe, code, name):
    assert cwe in cwes(rules_engine.scan_file(make(code, name)))


@pytest.mark.parametrize("code", [
    "return this.http.get(`${this.hostServer}/rest/products`)",   # a URL, not SQL
    "Address.findOne({ where: { UserId: req.body.UserId } })",      # Sequelize binds values
    "if (element.innerHTML === value) {",                           # a comparison
])
def test_javascript_rules_ignore_what_the_review_found_harmless(code):
    assert rules_engine.scan_file(make(code + "\n", "a.ts")) == []


def test_typescript_type_annotations_do_not_hide_the_input():
    code = ("let criteria: any = req.query.q\n"
            "models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${criteria}%'`)\n")
    assert taint_lite.is_traced(make(code, "search.ts"), 2)


def test_a_node_env_folder_and_key_files_are_scanned(tmp_path):
    (tmp_path / "config" / "env").mkdir(parents=True)
    (tmp_path / "config" / "env" / "all.js").write_text("module.exports = {}\n", encoding="utf-8")
    (tmp_path / "venv_like" / "env").mkdir(parents=True)                # a real virtualenv
    (tmp_path / "venv_like" / "env" / "pyvenv.cfg").write_text("home = x\n", encoding="utf-8")
    (tmp_path / "venv_like" / "env" / "lib.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "server.key").write_text("-----BEGIN RSA PRIVATE KEY-----\n", encoding="utf-8")
    scanned = sorted(f.rel for f in walk_project(str(tmp_path)))
    assert scanned == ["config/env/all.js", "server.key"]


def test_eval_rule_does_not_match_the_word_evaluations():
    assert rules_engine.scan_file(make('<p class="lead">Performance evaluations</p>\n',
                                       "a.html.erb")) == []


@pytest.mark.parametrize("name,traced,fixed", [
    ("a.rb", "path = params[:url]\nredirect_to path\n", "path = root_path\nredirect_to path\n"),
    ("a.rb", "path = params[:name]\nsend_file path\n", "path = 'report.pdf'\nsend_file path\n"),
    ("A.java", 'String url = request.getParameter("u");\nresponse.sendRedirect(url);\n',
     'String url = "/home";\nresponse.sendRedirect(url);\n'),
    ("a.jsp", '<% String q = request.getParameter("q"); %>\n<p><%= q %></p>\n',
     '<% String q = "fixed"; %>\n<p><%= q %></p>\n'),
    ("p.ts", "const url = req.body.imageUrl\nconst r = await fetch(url)\n",
     "const url = '/health'\nconst r = await fetch(url)\n"),
])
def test_sink_rules_fire_only_when_request_input_reaches_them(name, traced, fixed):
    assert rules_engine.scan_file(make(traced, name))
    assert rules_engine.scan_file(make(fixed, name)) == []


# ------------------------------------------------------------------ input tracing details
def test_words_in_a_string_literal_are_not_variables():
    java = 'String url = request.getParameter("url");\nout.print("Missing url parameter");\n'
    assert not taint_lite.is_traced(make(java, "A.java"), 2)
    php = "$name = $_GET['name'];\n$sql = \"SELECT * FROM t WHERE n = '$name'\";\n"
    assert taint_lite.is_traced(make(php, "a.php"), 2)          # interpolation still counts
    js = "const id = req.query.id;\nconst q = `SELECT * FROM t WHERE id = ${id}`;\n"
    assert taint_lite.is_traced(make(js, "a.js"), 2)


def test_sql_escaping_counts_as_a_sanitizer():
    php = ("$u = mysqli_real_escape_string($db, $_POST['u']);\n"
           "$q = \"SELECT * FROM users WHERE user = '$u'\";\n")
    assert not taint_lite.is_traced(make(php, "a.php"), 2)


# ------------------------------------------------------------------ secrets details
@pytest.mark.parametrize("name,line", [
    ("a.php", "$q = \"UPDATE users SET password = '$pass_new' WHERE user = '\" . $u . \"';\""),
    ("routes.rb", 'get "forgot_password" => "password_resets#forgot_password"'),
    ("frontend/src/assets/i18n/tr.json", '"INITIAL_TOKEN_TOOLTIP": "Kimlik tokeninizi giriniz.",'),
    ("app/strings.json", '"LABEL_PASSWORD": "Kennwort",'),
    ("static/js/libs/mode-java.js", 'token: "keyword.operator",'),
])
def test_variables_and_route_targets_are_not_secrets(name, line):
    assert secrets.scan_file(make(line + "\n", name)) == []


def test_placeholder_line_recognizes_values_that_are_not_secrets():
    assert secrets.placeholder_line("app.config['SECRET_KEY'] = 'your-secret-key-here'")
    assert secrets.placeholder_line('return jsonify({"secret": None})')
    assert not secrets.placeholder_line('db_password = "Pr0d-DB-pass!2024"')


# ------------------------------------------------------------------ C/C++ memory checks
C_VULNERABLE = """\
struct Image { int width; int height; char data[10]; };
void spin(void) {
    char buf[64];
    spin();
}
int process(FILE *fp) {
    struct Image img;
    fread(&img, sizeof(img), 1, fp);
    int size = img.width * img.height;
    char *p = (char *)malloc(size);
    memcpy(p, img.data, sizeof(img.data));
    free(p);
    free(p);
    p[0] = 'a';
    int ratio = img.width / img.height;
    char small[10];
    small[ratio] = 'c';
    char c = small[ratio];
    char *q = malloc(16);
    q = NULL;
    return 0;
}
void copy_packet(const char *data, size_t len) {
    char packet[256];
    memcpy(packet, data, len);
}
int *make_table(int count) {
    return malloc(count * sizeof(int));
}
"""

C_SAFE = """\
int process(FILE *fp) {
    struct Image img;
    if (fread(&img, sizeof(img), 1, fp) != 1) return -1;
    if (img.height == 0 || img.width > 1000 || img.height > 1000) return -1;
    int ratio = img.width / img.height;
    char *p = malloc(64);
    if (p == NULL) return -1;
    free(p);
    p = NULL;
    free(p);
    char small[10];
    if (ratio < 10) small[ratio] = 'c';
    return 0;
}
int error_path(int fail) {
    char *p = malloc(10);
    if (fail) {
        free(p);
        return -1;
    }
    p[0] = 'x';
    free(p);
    return 0;
}
void copy_checked(const char *data, size_t len) {
    char packet[256];
    if (len > sizeof(packet)) return;
    memcpy(packet, data, len);
}
char *dup_line(const char *s, size_t len) {
    char *out = malloc(len + 1);
    memcpy(out, s, len);
    out[len] = 0;
    return out;
}
#define RUN(group) \\
    { void RUN_##group(void); RUN_##group(); }
"""


def test_c_memory_checks_find_each_weakness():
    from sca.engines import c_memory
    found = {(f.line, f.rule_id) for f in c_memory.scan_file(make(C_VULNERABLE, "img.c"))}
    assert found == {
        (4, "C-MEM-RECURSION"), (10, "C-MEM-ALLOC-OVERFLOW"), (11, "C-MEM-COPY-SOURCE-SIZE"),
        (13, "C-MEM-DOUBLE-FREE"), (14, "C-MEM-UAF"), (15, "C-MEM-DIV-ZERO"),
        (17, "C-MEM-OOB-WRITE"), (18, "C-MEM-OOB-READ"), (20, "C-MEM-LEAK"),
        (25, "C-MEM-COPY-LENGTH"), (28, "C-MEM-ALLOC-PARAM")}


def test_c_memory_checks_stay_quiet_on_correct_code():
    from sca.engines import c_memory
    assert c_memory.scan_file(make(C_SAFE, "ok.c")) == []
