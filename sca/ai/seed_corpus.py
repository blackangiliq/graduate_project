"""Built-in training data for the ML classifier.

The corpus is SYNTHETIC: each entry is a code template with a vulnerable and a safe form,
expanded with random identifier names so the model learns the shape of the code
(concatenation into execute(), shell=True, innerHTML = variable ...) and not the names.

It exists so the classifier works out of the box. It is small and artificial, so do not
report its accuracy as a research result. For the thesis, train on a real dataset:

    python -m sca train --dataset path/to/primevul_train.jsonl

(see docs/GUIDE_AR.md).
"""
from __future__ import annotations

import random
from typing import List, Tuple

# <<v>> variable, <<t>> table, <<c>> column, <<f>> function-ish name, <<o>> object
VULNERABLE = [
    # --- SQL injection
    'cursor.execute("SELECT * FROM <<t>> WHERE <<c>> = \'" + <<v>> + "\'")',
    'cursor.execute(f"SELECT * FROM <<t>> WHERE <<c>> = {<<v>>}")',
    'cursor.execute("DELETE FROM <<t>> WHERE <<c>> = %s" % <<v>>)',
    'db.execute("UPDATE <<t>> SET <<c>> = \'{}\'".format(<<v>>))',
    '<<o>>.query("SELECT * FROM <<t>> WHERE <<c>> = " + <<v>>)',
    '<<o>>.query(`SELECT * FROM <<t>> WHERE <<c>> = ${<<v>>}`)',
    '$result = mysqli_query($conn, "SELECT * FROM <<t>> WHERE <<c>> = \'$<<v>>\'");',
    '$sql = "SELECT * FROM <<t>> WHERE <<c>> = " . $_GET["<<v>>"];',
    'stmt.executeQuery("SELECT * FROM <<t>> WHERE <<c>> = \'" + <<v>> + "\'");',
    'String sql = "SELECT * FROM <<t>> WHERE <<c>> = " + <<v>>;',
    'db.Query("SELECT * FROM <<t>> WHERE <<c>> = " + <<v>>)',
    # --- command injection
    'os.system("ping -c 1 " + <<v>>)',
    'os.system(f"convert {<<v>>} out.png")',
    'subprocess.run("tar xf " + <<v>>, shell=True)',
    'subprocess.call(f"rm -rf {<<v>>}", shell=True)',
    'exec("ls " + <<v>>, callback)',
    'child_process.execSync(`git clone ${<<v>>}`)',
    'system("ping " . $_GET["<<v>>"]);',
    '$out = shell_exec("nslookup " . $<<v>>);',
    'Runtime.getRuntime().exec("cmd /c " + <<v>>);',
    'system(<<v>>);',
    # --- code injection
    'result = eval(<<v>>)',
    'exec(<<v>>)',
    'eval(req.query.<<v>>)',
    'eval($_POST["<<v>>"]);',
    'const fn = new Function(<<v>>)',
    # --- XSS
    'element.innerHTML = <<v>>;',
    'document.getElementById("<<c>>").innerHTML = "<b>" + <<v>> + "</b>";',
    'document.write(<<v>>)',
    'res.send("<h1>" + req.query.<<v>> + "</h1>")',
    'echo $_GET["<<v>>"];',
    'echo "<p>" . $_POST["<<v>>"] . "</p>";',
    'return f"<h1>Hello {<<v>>}</h1>"',
    'response.getWriter().println("<p>" + request.getParameter("<<v>>") + "</p>");',
    'return render_template_string("<p>" + <<v>> + "</p>")',
    # --- path traversal / file inclusion
    'open(os.path.join(UPLOAD_DIR, request.args["<<v>>"]))',
    'fs.readFile(req.query.<<v>>, cb)',
    'res.sendFile(req.params.<<v>>)',
    'include($_GET["<<v>>"]);',
    'readfile($_GET["<<v>>"]);',
    'new File(baseDir + request.getParameter("<<v>>"))',
    # --- deserialization
    '<<o>> = pickle.loads(<<v>>)',
    'data = yaml.load(<<v>>)',
    '$obj = unserialize($_COOKIE["<<v>>"]);',
    'ObjectInputStream in = new ObjectInputStream(<<v>>);',
    # --- weak crypto / randomness
    'digest = hashlib.md5(<<v>>.encode()).hexdigest()',
    'hashlib.sha1(password.encode())',
    'crypto.createHash("md5").update(<<v>>)',
    '$hash = md5($password);',
    'MessageDigest md = MessageDigest.getInstance("MD5");',
    'Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");',
    'token = str(random.randint(100000, 999999))',
    'const token = Math.random().toString(36)',
    '$token = md5(uniqid());',
    # --- TLS / misconfiguration
    'requests.get(<<v>>, verify=False)',
    'https.request({host: <<v>>, rejectUnauthorized: false})',
    'curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);',
    'app.run(debug=True)',
    'jwt.decode(<<v>>, options={"verify_signature": False})',
    # --- memory safety
    'strcpy(<<c>>, <<v>>);',
    'gets(<<v>>);',
    'sprintf(<<c>>, "%s", <<v>>);',
    'printf(<<v>>);',
    'scanf("%s", <<v>>);',
    'strcat(<<c>>, <<v>>);',
    # --- secrets
    '<<c>>_password = "S3cr3t!<<v>>99"',
    'const apiKey = "9f8a7c6b5d4e3f2a1b0c<<v>>";',
    # --- redirect / ssrf
    'return redirect(request.args.get("<<v>>"))',
    'res.redirect(req.query.<<v>>)',
    'requests.get(request.args["<<v>>"])',
    'header("Location: " . $_GET["<<v>>"]);',
]

SAFE = [
    # --- parameterized SQL
    'cursor.execute("SELECT * FROM <<t>> WHERE <<c>> = %s", (<<v>>,))',
    'cursor.execute("SELECT * FROM <<t>> WHERE <<c>> = ?", [<<v>>])',
    'cursor.execute("DELETE FROM <<t>> WHERE <<c>> = :<<c>>", {"<<c>>": <<v>>})',
    'db.execute(text("UPDATE <<t>> SET <<c>> = :v"), {"v": <<v>>})',
    '<<o>>.query("SELECT * FROM <<t>> WHERE <<c>> = ?", [<<v>>])',
    '<<o>>.query("SELECT * FROM <<t>> WHERE <<c>> = $1", [<<v>>])',
    '$stmt = $pdo->prepare("SELECT * FROM <<t>> WHERE <<c>> = ?");',
    '$stmt->execute([$<<v>>]);',
    'PreparedStatement ps = conn.prepareStatement("SELECT * FROM <<t>> WHERE <<c>> = ?");',
    'ps.setString(1, <<v>>);',
    'db.Query("SELECT * FROM <<t>> WHERE <<c>> = ?", <<v>>)',
    'rows = <<o>>.objects.filter(<<c>>=<<v>>)',
    # --- safe process execution
    'subprocess.run(["ping", "-c", "1", <<v>>], check=True)',
    'subprocess.run(["tar", "xf", <<v>>])',
    'subprocess.check_output(["git", "status"])',
    'execFile("git", ["clone", <<v>>], callback)',
    'os.system("clear")',
    '$out = shell_exec("nslookup " . escapeshellarg($<<v>>));',
    'new ProcessBuilder("ls", "-l", <<v>>).start();',
    # --- safe parsing
    'result = ast.literal_eval(<<v>>)',
    'data = json.loads(<<v>>)',
    'const data = JSON.parse(<<v>>)',
    'data = yaml.safe_load(<<v>>)',
    '$obj = json_decode($<<v>>, true);',
    # --- encoded output
    'element.textContent = <<v>>;',
    'document.getElementById("<<c>>").textContent = <<v>>;',
    'element.innerHTML = DOMPurify.sanitize(<<v>>);',
    'res.json({<<c>>: req.query.<<v>>})',
    'echo htmlspecialchars($_GET["<<v>>"], ENT_QUOTES, "UTF-8");',
    'return render_template("<<t>>.html", <<c>>=<<v>>)',
    'return f"<h1>Hello {escape(<<v>>)}</h1>"',
    'response.getWriter().println(Encode.forHtml(<<v>>));',
    # --- safe file handling
    'open(os.path.join(UPLOAD_DIR, secure_filename(<<v>>)))',
    'with open("config/<<t>>.json") as handle:',
    'fs.readFile(path.join(__dirname, "<<t>>.json"), cb)',
    'res.sendFile(path.basename(<<v>>), {root: uploadDir})',
    'include("templates/<<t>>.php");',
    'new File(baseDir, FilenameUtils.getName(<<v>>))',
    # --- strong crypto / randomness
    'digest = hashlib.sha256(<<v>>.encode()).hexdigest()',
    'hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())',
    'crypto.createHash("sha256").update(<<v>>)',
    '$hash = password_hash($password, PASSWORD_DEFAULT);',
    'MessageDigest md = MessageDigest.getInstance("SHA-256");',
    'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");',
    'token = secrets.token_urlsafe(32)',
    'const token = crypto.randomBytes(32).toString("hex")',
    '$token = bin2hex(random_bytes(32));',
    'SecureRandom random = new SecureRandom();',
    'index = random.randint(0, len(<<v>>) - 1)',
    # --- TLS / configuration
    'requests.get(<<v>>, timeout=10)',
    'https.request({host: <<v>>, rejectUnauthorized: true})',
    'app.run(debug=False)',
    'app.run(debug=os.environ.get("FLASK_DEBUG") == "1")',
    'jwt.decode(<<v>>, key, algorithms=["HS256"])',
    # --- bounded C functions
    'strncpy(<<c>>, <<v>>, sizeof(<<c>>) - 1);',
    'fgets(<<v>>, sizeof(<<v>>), stdin);',
    'snprintf(<<c>>, sizeof(<<c>>), "%s", <<v>>);',
    'printf("%s", <<v>>);',
    'scanf("%63s", <<v>>);',
    'strlcat(<<c>>, <<v>>, sizeof(<<c>>));',
    # --- configuration from the environment
    '<<c>>_password = os.environ["DB_PASSWORD"]',
    'const apiKey = process.env.API_KEY;',
    # --- ordinary code
    'return redirect(url_for("<<t>>"))',
    'res.redirect("/<<t>>")',
    'response = requests.get("https://api.example.com/<<t>>", timeout=5)',
    'for <<v>> in <<o>>:',
    '<<v>> = <<o>>.get("<<c>>", None)',
    'logger.info("processing %s", <<v>>)',
    'return {"<<c>>": <<v>>, "status": "ok"}',
    'if <<v>> is None: raise ValueError("<<c>> is required")',
    'const <<v>> = <<o>>.map(item => item.<<c>>);',
    'total += int(<<v>>)',
    'print(f"Loaded {len(<<v>>)} rows from <<t>>")',
    'console.log("user", <<v>>.<<c>>)',
]

_VARS = ["user_id", "name", "value", "param", "q", "item", "data", "inp", "uid", "target",
         "filename", "host", "payload", "key", "arg", "text", "s", "x", "term", "ref"]
_TABLES = ["users", "orders", "products", "accounts", "logs", "sessions", "items", "posts"]
_COLS = ["id", "name", "email", "title", "status", "owner", "buf", "dest", "field"]
_OBJS = ["db", "conn", "pool", "client", "repo", "rows", "records", "store"]


def _fill(template: str, rng: random.Random) -> str:
    return (template.replace("<<v>>", rng.choice(_VARS))
            .replace("<<t>>", rng.choice(_TABLES))
            .replace("<<c>>", rng.choice(_COLS))
            .replace("<<o>>", rng.choice(_OBJS))
            .replace("<<f>>", rng.choice(_VARS)))


def build_corpus(variants: int = 6, seed: int = 7) -> Tuple[List[str], List[int]]:
    """Return (code_lines, labels) where label 1 = vulnerable and 0 = safe."""
    rng = random.Random(seed)
    texts: List[str] = []
    labels: List[int] = []
    for label, templates in ((1, VULNERABLE), (0, SAFE)):
        for template in templates:
            seen = set()
            for _ in range(variants):
                line = _fill(template, rng)
                if line not in seen:
                    seen.add(line)
                    texts.append(line)
                    labels.append(label)
    return texts, labels
