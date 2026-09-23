"""Security pattern scanner tests."""

from gdprlint.scanners.security import SecurityScanner


def scan(text: str, file: str = "app.py"):
    return list(SecurityScanner().scan_line(file, 5, text))


def rules(findings):
    return {f.rule for f in findings}


def test_eval_js():
    fs = scan("const x = eval(userInput);", file="app.js")
    assert "SECURITY.EVAL" in rules(fs)


def test_eval_python():
    fs = scan("result = eval(expr)", file="main.py")
    assert "SECURITY.EVAL" in rules(fs)


def test_exec_python():
    fs = scan("exec(compile(code, '<string>', 'exec'))", file="main.py")
    assert "SECURITY.EXEC" in rules(fs)


def test_os_system():
    fs = scan('os.system("ls " + path)', file="main.py")
    assert "SECURITY.OS_SYSTEM" in rules(fs)


def test_subprocess_shell_true():
    fs = scan("subprocess.run(cmd, shell=True)", file="main.py")
    assert "SECURITY.SUBPROCESS_SHELL" in rules(fs)


def test_subprocess_shell_false_safe():
    fs = scan("subprocess.run(['ls'], shell=False)", file="main.py")
    assert "SECURITY.SUBPROCESS_SHELL" not in rules(fs)


def test_child_process_exec():
    fs = scan("child_process.exec(cmd, cb);", file="index.js")
    assert "SECURITY.CHILD_PROCESS_EXEC" in rules(fs)


def test_dangerously_set_inner_html():
    fs = scan("<div dangerouslySetInnerHTML={{__html: raw}} />", file="App.tsx")
    assert "SECURITY.DANGEROUS_HTML" in rules(fs)


def test_sql_concat_flagged():
    fs = scan('query = "SELECT * FROM users WHERE id = " + user_id', file="dao.py")
    assert "SECURITY.SQL_CONCAT" in rules(fs)


def test_parameterized_query_not_sql_concat():
    fs = scan(
        'cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])',
        file="dao.py",
    )
    # May or may not flag depending on heuristic; prefer no SELECT...+ match
    assert "SECURITY.SQL_CONCAT" not in rules(fs)


def test_pickle_loads():
    fs = scan("obj = pickle.loads(data)", file="main.py")
    assert "SECURITY.PICKLE_LOADS" in rules(fs)


def test_yaml_unsafe():
    fs = scan("cfg = yaml.load(text)", file="main.py")
    assert "SECURITY.YAML_UNSAFE" in rules(fs)


def test_tls_verify_off():
    fs = scan("requests.get(url, verify=False)", file="main.py")
    assert "SECURITY.TLS_VERIFY_OFF" in rules(fs)


def test_cors_wildcard():
    fs = scan('Access-Control-Allow-Origin: *', file="server.js")
    assert "SECURITY.CORS_WILDCARD" in rules(fs)


def test_cors_express_empty():
    fs = scan("app.use(cors());", file="server.js")
    assert "SECURITY.CORS_WILDCARD" in rules(fs)


def test_cors_socket_origin_star():
    fs = scan('const io = new Server(server, { cors: { origin: "*" } });', file="s.js")
    assert "SECURITY.CORS_WILDCARD" in rules(fs)


def test_log_credential_interpolation():
    fs = scan(
        "console.log(`login - user: ${identifier}, Password: ${password}`);",
        file="api.ts",
    )
    assert "SECURITY.LOG_CREDENTIAL" in rules(fs)
    f = next(x for x in fs if x.rule == "SECURITY.LOG_CREDENTIAL")
    assert f.severity == "high"
    assert f.confidence == "high"


def test_log_credential_not_bare_keyword():
    fs = scan(
        'console.warn("GOOGLE_CLIENT_ID/SECRET not found in .env");',
        file="s.js",
    )
    assert "SECURITY.LOG_CREDENTIAL" not in rules(fs)


def test_localstorage_password_flagged():
    fs = scan(
        "localStorage.setItem('auth_data', JSON.stringify({ token, user, pass: password }));",
        file="api.ts",
    )
    assert "SECURITY.LOCALSTORAGE_SECRET" in rules(fs)
    f = next(x for x in fs if x.rule == "SECURITY.LOCALSTORAGE_SECRET")
    assert f.confidence == "high"


def test_localstorage_safe_theme_not_flagged():
    fs = scan('localStorage.setItem("theme", "dark");', file="ui.ts")
    assert "SECURITY.LOCALSTORAGE_SECRET" not in rules(fs)


def test_safe_crypto_code_no_noise():
    fs = scan("h = hashlib.sha256(data).hexdigest()", file="main.py")
    # weak hash rule may still catch sha1/md5 only
    assert "SECURITY.WEAK_HASH" not in rules(fs)
