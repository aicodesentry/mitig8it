"""mitig8it regression-test harness v1 for Python (contracts/test-harness-python-v1.md).

Standard library only, never part of a repair. Materialized at .mitig8it/harness.py; a test at
.mitig8it/regression/<finding>.test.py runs as `python3 .mitig8it/harness.py <test>` and does
`import harness as h`. It loads a repository module with flask, sqlite3, psycopg, sqlalchemy,
subprocess, os.system, os.environ, and open() faked and recorded, invokes plain functions or
Flask views, and asserts on what the module did.
"""
import builtins
import importlib.abc
import importlib.util
import inspect
import io
import json as _json
import os
import re
import sys
import traceback
import types
import urllib.parse

version = 1
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
db = types.SimpleNamespace(queries=[])
subprocess = types.SimpleNamespace(calls=[])
fs = types.SimpleNamespace(reads=[], writes=[])
flask = types.SimpleNamespace(routes=[])
env = types.SimpleNamespace(reads=[])
stubbed = []
_config = {}
_loaded_names = []
# `sys.argv` as the test process was started, so a load that supplied none restores it.
_real_argv = list(sys.argv)
_real_open = builtins.open
_real_system, _real_popen = os.system, os.popen
_STDLIB = getattr(sys, "stdlib_module_names", frozenset())


class HarnessAssertion(AssertionError):
    pass


def fail(message, detail=None):
    raise HarnessAssertion(message if detail is None else "%s: %r" % (message, detail))


def _reset():
    for items in (db.queries, subprocess.calls, fs.reads, fs.writes, flask.routes, env.reads, stubbed):
        del items[:]


def _cfg(key, default=None):
    return _config.get(key, default)


# --- recording environment -------------------------------------------------------------------
class _Environ(dict):
    def __getitem__(self, key):
        env.reads.append(key)
        try:
            return dict.__getitem__(self, key)
        except KeyError:
            raise KeyError(key) from None

    def get(self, key, default=None):
        env.reads.append(key)
        return dict.get(self, key, default)

    def __contains__(self, key):
        env.reads.append(key)
        return dict.__contains__(self, key)

    def copy(self):
        return dict(self)


# --- database fakes: sqlite3, psycopg2, psycopg, pymysql, sqlalchemy ---------------------------
def _rows():
    rows = _cfg("rows")
    return list(rows(db.queries[-1]) if callable(rows) else (rows or []))


def _record_query(api, sql, params):
    entry = {"api": api, "sql": str(sql), "params": params}
    db.queries.append(entry)
    return entry


class Cursor:
    def __init__(self, api):
        self._api, self._rows, self.rowcount, self.description, self.lastrowid, self.arraysize = api, [], -1, None, None, 1

    def execute(self, sql, params=None, *args, **kwargs):
        _record_query(self._api, sql, params)
        self._rows = _rows()
        self.rowcount = len(self._rows)
        return self

    def executemany(self, sql, seq_of_params, *args, **kwargs):
        _record_query(self._api, sql, [list(item) if isinstance(item, (list, tuple)) else item for item in seq_of_params])
        return self

    def executescript(self, sql):
        _record_query(self._api, sql, None)
        return self

    def fetchone(self):
        return self._rows.pop(0) if self._rows else None

    def fetchmany(self, size=None):
        taken, self._rows = self._rows[: size or self.arraysize], self._rows[size or self.arraysize :]
        return taken

    def fetchall(self):
        taken, self._rows = self._rows, []
        return taken

    def scalar(self):
        row = self.fetchone()
        return row[0] if isinstance(row, (list, tuple)) and row else row

    first = fetchone
    scalar_one = scalar

    def mappings(self):
        return self

    def close(self):
        pass

    def __iter__(self):
        return iter(self.fetchall())

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Connection:
    def __init__(self, api):
        self._api, self.row_factory, self.autocommit, self.closed = api, None, False, False

    def cursor(self, *args, **kwargs):
        return Cursor(self._api)

    def execute(self, sql, params=None, *args, **kwargs):
        return Cursor(self._api).execute(sql, params)

    def executemany(self, sql, seq, *args, **kwargs):
        return Cursor(self._api).executemany(sql, seq)

    def executescript(self, sql):
        return Cursor(self._api).executescript(sql)

    def begin(self):
        return self

    connect = begin

    def commit(self):
        pass

    rollback = close = commit

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Composable:
    def __init__(self, text):
        self.text = text

    def format(self, *args, **kwargs):
        return _Composable(self.text.format(*args, **kwargs))

    def join(self, items):
        return _Composable(self.text.join(str(item) for item in items))

    def as_string(self, *args):
        return self.text

    def __add__(self, other):
        return _Composable(self.text + str(other))

    def __str__(self):
        return self.text


def _db_module(name, paramstyle):
    module = types.ModuleType(name)
    module.paramstyle, module.apilevel, module.threadsafety = paramstyle, "2.0", 1
    module.connect = lambda *args, **kwargs: Connection(name)
    module.Connection, module.Cursor, module.Row = Connection, Cursor, tuple
    for error in ("Error", "Warning", "DatabaseError", "IntegrityError", "OperationalError", "ProgrammingError", "InterfaceError", "DataError", "InternalError", "NotSupportedError"):
        setattr(module, error, type(error, (Exception,), {}))
    module.PARSE_DECLTYPES, module.PARSE_COLNAMES = 1, 2
    sql = types.ModuleType(name + ".sql")
    sql.SQL, sql.Composed = _Composable, _Composable
    sql.Identifier = lambda *parts: _Composable(".".join('"%s"' % part for part in parts))
    sql.Literal = lambda value: _Composable(repr(value))
    sql.Placeholder = lambda name=None: _Composable("%%(%s)s" % name if name else "%s")
    extras = types.ModuleType(name + ".extras")
    extras.RealDictCursor = extras.DictCursor = extras.NamedTupleCursor = Cursor
    extras.execute_values = lambda cur, sql, argslist, *a, **k: cur.executemany(sql, argslist)
    module.sql, module.extras, module.rows = sql, extras, types.ModuleType(name + ".rows")
    module.rows.dict_row = module.rows.tuple_row = None
    return module


class _TextClause(_Composable):
    def bindparams(self, *args, **kwargs):
        return self

    columns = bindparams


class _Engine(Connection):
    def __init__(self):
        Connection.__init__(self, "sqlalchemy")

    def execute(self, statement, parameters=None, *args, **kwargs):
        return Cursor("sqlalchemy").execute(statement, parameters if parameters is not None else (kwargs or None))

    def exec_driver_sql(self, statement, parameters=None, *args, **kwargs):
        return self.execute(statement, parameters)

    def raw_connection(self):
        return Connection("sqlalchemy")


def _sqlalchemy_module():
    module = types.ModuleType("sqlalchemy")
    module.text, module.create_engine, module.Engine, module.Connection = _TextClause, lambda *a, **k: _Engine(), _Engine, _Engine
    module.engine = types.ModuleType("sqlalchemy.engine")
    module.engine.create_engine, module.engine.Engine = module.create_engine, _Engine
    module.exc = types.ModuleType("sqlalchemy.exc")
    module.exc.SQLAlchemyError = type("SQLAlchemyError", (Exception,), {})
    module.orm = types.ModuleType("sqlalchemy.orm")
    module.orm.Session = module.orm.sessionmaker = lambda *a, **k: _Engine()
    return module


# --- subprocess and os.system fakes -----------------------------------------------------------
def _record_call(fn, args, kwargs):
    via_shell = bool(kwargs.get("shell")) or isinstance(args, (str, bytes, os.PathLike))
    argv = None if isinstance(args, (str, bytes, os.PathLike)) else [str(item) for item in args]
    command = str(args) if argv is None else " ".join(argv)
    entry = {"fn": fn, "args": argv, "shell": via_shell, "command": command, "options": {k: v for k, v in kwargs.items() if k in ("shell", "cwd", "executable")}}
    subprocess.calls.append(entry)
    return entry


def _outcome(kwargs):
    text = bool(kwargs.get("text") or kwargs.get("universal_newlines") or kwargs.get("encoding") or kwargs.get("errors"))
    out, err = str(_cfg("stdout", "")), str(_cfg("stderr", ""))
    return (out if text else out.encode(), err if text else err.encode(), int(_cfg("code", 0)))


def _subprocess_module():
    module = types.ModuleType("subprocess")
    module.PIPE, module.STDOUT, module.DEVNULL = -1, -2, -3

    class CalledProcessError(Exception):
        def __init__(self, returncode, cmd, output=None, stderr=None):
            Exception.__init__(self, "Command %r returned non-zero exit status %s" % (cmd, returncode))
            self.returncode, self.cmd, self.output, self.stdout, self.stderr = returncode, cmd, output, output, stderr

    class CompletedProcess:
        def __init__(self, args, returncode, stdout=None, stderr=None):
            self.args, self.returncode, self.stdout, self.stderr = args, returncode, stdout, stderr

        def check_returncode(self):
            if self.returncode:
                raise CalledProcessError(self.returncode, self.args, self.stdout, self.stderr)

    class Popen:
        def __init__(self, args, *a, **kwargs):
            _record_call("Popen", args, kwargs)
            out, err, code = _outcome(kwargs)
            self.args, self.returncode, self.pid = args, None, 4242
            self._out, self._err, self._code = out, err, code
            self.stdout = io.StringIO(out) if isinstance(out, str) else io.BytesIO(out)
            self.stderr = io.StringIO(err) if isinstance(err, str) else io.BytesIO(err)
            self.stdin = io.StringIO()

        def communicate(self, input=None, timeout=None):
            self.returncode = self._code
            return self._out, self._err

        def wait(self, timeout=None):
            self.returncode = self._code
            return self._code

        def poll(self):
            return self.returncode

        def kill(self):
            pass

        terminate = send_signal = kill

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.wait()
            return False

    def run(args, *a, **kwargs):
        _record_call("run", args, kwargs)
        out, err, code = _outcome(kwargs)
        if kwargs.get("check") and code:
            raise CalledProcessError(code, args, out, err)
        return CompletedProcess(args, code, out if kwargs.get("capture_output") or kwargs.get("stdout") is not None else None, err if kwargs.get("capture_output") or kwargs.get("stderr") is not None else None)

    def call(args, *a, **kwargs):
        return run(args, *a, **kwargs).returncode

    def check_call(args, *a, **kwargs):
        return run(args, *a, check=True, **kwargs).returncode

    def check_output(args, *a, **kwargs):
        return run(args, *a, check=True, capture_output=True, **kwargs).stdout

    def getstatusoutput(cmd):
        _record_call("getstatusoutput", str(cmd), {"shell": True})
        return int(_cfg("code", 0)), str(_cfg("stdout", ""))

    module.CalledProcessError, module.CompletedProcess, module.Popen = CalledProcessError, CompletedProcess, Popen
    module.TimeoutExpired = type("TimeoutExpired", (Exception,), {})
    module.SubprocessError = type("SubprocessError", (Exception,), {})
    module.run, module.call, module.check_call, module.check_output = run, call, check_call, check_output
    module.getstatusoutput, module.getoutput = getstatusoutput, lambda cmd: getstatusoutput(cmd)[1]
    module.list2cmdline = lambda seq: " ".join(str(item) for item in seq)
    return module


def _fake_system(command):
    _record_call("os.system", str(command), {"shell": True})
    return int(_cfg("code", 0))


def _fake_popen(command, mode="r", buffering=-1):
    _record_call("os.popen", str(command), {"shell": True})
    return io.StringIO(str(_cfg("stdout", "")))


# --- open() fake ------------------------------------------------------------------------------
def _content(path):
    content = _cfg("content", "")
    return content(path) if callable(content) else content


def _exists(path):
    exists = _cfg("exists", True)
    return bool(exists(path)) if callable(exists) else exists is not False


def _fake_open(file, mode="r", *args, **kwargs):
    if not _config or isinstance(file, int):
        return _real_open(file, mode, *args, **kwargs)
    raw = os.fspath(file)
    raw = raw.decode() if isinstance(raw, bytes) else str(raw)
    entry = {"path": raw, "resolved": os.path.realpath(raw), "mode": mode}
    if any(flag in mode for flag in "wax+"):
        fs.writes.append(entry)
        return io.BytesIO() if "b" in mode else io.StringIO()
    fs.reads.append(entry)
    if not _exists(raw):
        raise FileNotFoundError(2, "No such file or directory", raw)
    content = _content(raw)
    if "b" in mode:
        return io.BytesIO(content if isinstance(content, bytes) else str(content).encode())
    return io.StringIO(content.decode() if isinstance(content, bytes) else str(content))


# --- flask fake -------------------------------------------------------------------------------
class HTTPException(Exception):
    def __init__(self, code=500, description=None):
        Exception.__init__(self, "%s %s" % (code, description or ""))
        self.code, self.description = code, description


class Response:
    def __init__(self, response=None, status=200, headers=None, mimetype=None, content_type=None, **kwargs):
        self.status_code = int(status[0] if isinstance(status, tuple) else status)
        self.headers = {str(k).lower(): v for k, v in dict(headers or {}).items()}
        if mimetype or content_type:
            self.headers["content-type"] = mimetype or content_type
        self.data = response if isinstance(response, (str, bytes)) else ("".join(response) if response is not None else "")
        self.body = self.data

    def set_cookie(self, *args, **kwargs):
        pass

    delete_cookie = set_cookie

    def get_json(self, silent=True):
        try:
            return _json.loads(self.data)
        except (TypeError, ValueError):
            return None

    @property
    def status(self):
        return str(self.status_code)


class _MultiDict(dict):
    def getlist(self, key):
        value = self.get(key)
        return list(value) if isinstance(value, (list, tuple)) else ([] if value is None else [value])

    def to_dict(self, flat=True):
        return dict(self)


class _Request:
    method = path = url = "GET"
    remote_addr = "127.0.0.1"

    def __init__(self):
        self.args, self.form, self.values, self.headers, self.files, self.cookies = _MultiDict(), _MultiDict(), _MultiDict(), _MultiDict(), _MultiDict(), _MultiDict()
        self.json, self.data, self.view_args, self.endpoint = None, b"", {}, None

    def get_json(self, force=False, silent=False, cache=True):
        return self.json

    def get_data(self, as_text=False, **kwargs):
        return self.data.decode() if as_text and isinstance(self.data, bytes) else self.data

    @property
    def is_json(self):
        return self.json is not None


request = _Request()


def abort(code, description=None, **kwargs):
    raise HTTPException(code, description)


def jsonify(*args, **kwargs):
    data = args[0] if len(args) == 1 else (list(args) if args else kwargs)
    return Response(_json.dumps(data), 200, {"content-type": "application/json"})


def make_response(*args):
    return _to_response(args[0] if len(args) == 1 else args)


def redirect(location, code=302, **kwargs):
    return Response("", code, {"location": location})


def send_file(path_or_file, mimetype=None, as_attachment=False, download_name=None, **kwargs):
    if isinstance(path_or_file, (str, bytes, os.PathLike)):
        with _fake_open(path_or_file, "rb") as handle:
            return Response(handle.read(), 200, {"content-type": mimetype or "application/octet-stream"})
    return Response(path_or_file.read(), 200, {"content-type": mimetype or "application/octet-stream"})


def send_from_directory(directory, path, **kwargs):
    return send_file(os.path.join(str(directory), str(path)), **kwargs)


def _rule_regex(rule):
    pattern = re.sub(r"<(?:(\w+):)?(\w+)>", lambda m: "(?P<%s>%s)" % (m.group(2), ".+" if m.group(1) == "path" else "[^/]+"), rule.rstrip("/") or "/")
    return re.compile("^" + pattern + "/?$")


class Flask:
    def __init__(self, import_name="app", url_prefix=None, **kwargs):
        self.name, self.import_name, self.config, self.url_prefix = import_name, import_name, {}, url_prefix or ""
        self.routes, self.logger, self.jinja_env = flask.routes, types.SimpleNamespace(info=print, warning=print, error=print, debug=print, exception=print), None

    def add_url_rule(self, rule, endpoint=None, view_func=None, methods=None, **kwargs):
        methods = [str(m).upper() for m in (methods or ["GET"])]
        if "GET" in methods and "HEAD" not in methods:
            methods.append("HEAD")
        self.routes.append({"rule": self.url_prefix + rule, "methods": methods, "view": view_func, "endpoint": endpoint or getattr(view_func, "__name__", None)})

    def route(self, rule, **options):
        def decorator(view):
            self.add_url_rule(rule, options.pop("endpoint", None), view, **options)
            return view

        return decorator

    def get(self, rule, **options):
        return self.route(rule, methods=["GET"], **options)

    def post(self, rule, **options):
        return self.route(rule, methods=["POST"], **options)

    def put(self, rule, **options):
        return self.route(rule, methods=["PUT"], **options)

    def delete(self, rule, **options):
        return self.route(rule, methods=["DELETE"], **options)

    def patch(self, rule, **options):
        return self.route(rule, methods=["PATCH"], **options)

    def register_blueprint(self, blueprint, url_prefix=None, **options):
        for entry in self.routes:
            if url_prefix and entry.get("blueprint") is blueprint and not blueprint.url_prefix:
                entry["rule"] = url_prefix + entry["rule"]

    def _passthrough(self, *args, **kwargs):
        return args[0] if args and callable(args[0]) else (lambda fn: fn)

    errorhandler = before_request = after_request = teardown_request = context_processor = template_filter = _passthrough
    before_first_request = teardown_appcontext = url_value_preprocessor = _passthrough

    def run(self, *args, **kwargs):
        pass

    def app_context(self):
        return _Context()

    test_request_context = app_context


class Blueprint(Flask):
    def __init__(self, name, import_name="app", url_prefix=None, **kwargs):
        Flask.__init__(self, import_name, url_prefix, **kwargs)
        self.name = name

    def add_url_rule(self, rule, endpoint=None, view_func=None, methods=None, **kwargs):
        Flask.add_url_rule(self, rule, endpoint, view_func, methods, **kwargs)
        self.routes[-1]["blueprint"] = self


class _Context:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def push(self):
        pass

    pop = push


def _flask_module():
    module = types.ModuleType("flask")
    module.Flask, module.Blueprint, module.request, module.Response = Flask, Blueprint, request, Response
    module.abort, module.jsonify, module.make_response, module.redirect = abort, jsonify, make_response, redirect
    module.send_file, module.send_from_directory = send_file, send_from_directory
    module.render_template = lambda name, **context: "template:%s" % name
    module.render_template_string = lambda source, **context: str(source)
    module.url_for = lambda endpoint, **values: "/" + str(endpoint)
    module.g, module.session, module.current_app = types.SimpleNamespace(), _MultiDict(), Flask("app")
    module.flash = lambda *a, **k: None
    module.escape = module.Markup = str
    return module


def _to_response(value):
    if isinstance(value, Response):
        return value
    if isinstance(value, tuple):
        body = _to_response(value[0])
        for extra in value[1:]:
            if isinstance(extra, int):
                body.status_code = extra
            elif isinstance(extra, dict):
                body.headers.update({str(k).lower(): v for k, v in extra.items()})
        return body
    if isinstance(value, (dict, list)):
        return jsonify(value)
    if value is None:
        return Response("", 200)
    return Response(value if isinstance(value, (str, bytes)) else str(value), 200)


def invoke(app, method, rule, params=None, query=None, json=None, form=None, data=None, headers=None):
    """Calls the view recorded for `method` and `rule` with a fake request; returns a Response."""
    method = str(method).upper()
    params = dict(params or {})
    path = rule
    for key, value in params.items():
        path = path.replace("<%s>" % key, str(value))
        path = re.sub(r"<\w+:%s>" % key, str(value), path)
    for entry in flask.routes:
        if entry["view"] is None or method not in entry["methods"]:
            continue
        match = _rule_regex(entry["rule"]).match(path.split("?")[0])
        if match is None and entry["rule"] != rule:
            continue
        view_args = {k: urllib.parse.unquote(v) for k, v in (match.groupdict() if match else {}).items()}
        view_args.update(params)
        for name, converter in re.findall(r"<(\w+):(\w+)>", entry["rule"]):
            if name == "int" and converter in view_args and str(view_args[converter]).lstrip("-").isdigit():
                view_args[converter] = int(view_args[converter])
        request.__init__()
        request.method, request.path, request.url, request.endpoint, request.view_args = method, path, path, entry["endpoint"], view_args
        request.args = _MultiDict({k: urllib.parse.unquote(v) if isinstance(v, str) else v for k, v in dict(query or {}).items()})
        request.form = _MultiDict(dict(form or {}))
        request.values = _MultiDict({**request.args, **request.form})
        request.headers = _MultiDict({str(k).title(): v for k, v in dict(headers or {}).items()})
        request.json = json
        request.data = data if isinstance(data, bytes) else (str(data).encode() if data is not None else (_json.dumps(json).encode() if json is not None else b""))
        try:
            return _to_response(entry["view"](**view_args))
        except HTTPException as error:
            return Response(error.description or "", error.code)
    raise HarnessAssertion("harness.invoke: no %s view recorded for %s" % (method, rule))


# --- auto-stubs for third-party imports the sandbox does not carry ------------------------------
# A stub is a class rather than an object, because a module under test does not only call what it
# imports: it inherits from it. `class NewUserForm(UserCreationForm)` is the first statement of
# pygoat's `introduction/forms.py`, and a stub object there is a metaclass Python calls with the
# name, the bases and the namespace, which ended the import with a TypeError about argument
# counts. As a class it is a base like any other, it still answers every attribute with another
# stub, and calling it yields an instance instead of raising.
class _StubMeta(type):
    def __getattr__(cls, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return _stub(cls.__name__ + "." + name)

    def __iter__(cls):
        return iter(())

    def __repr__(cls):
        return "<harness stub %s>" % cls.__name__


class _Stub(metaclass=_StubMeta):
    def __init__(self, *args, **kwargs):
        pass

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return _stub(type(self).__name__ + "." + name)

    def __iter__(self):
        return iter(())

    def __repr__(self):
        return "<harness stub %s>" % type(self).__name__


def _stub(name):
    return _StubMeta(name, (_Stub,), {})


class _StubModule(types.ModuleType):
    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return _stub(self.__name__ + "." + name)


class _StubLoader(importlib.abc.Loader):
    def create_module(self, spec):
        return _StubModule(spec.name)

    def exec_module(self, module):
        module.__path__ = []


class _AutoStubFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        top = fullname.split(".")[0]
        if not _cfg("auto_stub") or top in _STDLIB or top == "harness":
            return None
        stubbed.append(fullname)
        return importlib.util.spec_from_loader(fullname, _StubLoader(), is_package=True)


# --- loading ----------------------------------------------------------------------------------
def _install(real, stubs):
    fakes = {
        "flask": _flask_module,
        "sqlite3": lambda: _db_module("sqlite3", "qmark"),
        "psycopg2": lambda: _db_module("psycopg2", "pyformat"),
        "psycopg": lambda: _db_module("psycopg", "pyformat"),
        "pymysql": lambda: _db_module("pymysql", "pyformat"),
        "sqlalchemy": _sqlalchemy_module,
        "subprocess": _subprocess_module,
    }
    for name, factory in fakes.items():
        if name in real:
            continue
        module = factory()
        sys.modules[name] = module
        for attribute, value in vars(module).items():
            if isinstance(value, types.ModuleType) and value.__name__.startswith(name + "."):
                sys.modules[value.__name__] = value
    for name, value in dict(stubs or {}).items():
        sys.modules[name] = value if isinstance(value, types.ModuleType) else _module_from(name, value)
    os.system, os.popen = (_real_system, _real_popen) if "os.system" in real else (_fake_system, _fake_popen)
    if not isinstance(os.environ, _Environ):
        os.environ = _Environ(os.environ)
        os.getenv = lambda key, default=None: os.environ.get(key, default)
    builtins.open = io.open = _real_open if "open" in real else _fake_open
    if not any(isinstance(finder, _AutoStubFinder) for finder in sys.meta_path):
        sys.meta_path.append(_AutoStubFinder())


def _module_from(name, value):
    module = types.ModuleType(name)
    for key, item in (value.items() if isinstance(value, dict) else vars(value).items()):
        if not key.startswith("__"):
            setattr(module, key, item)
    return module


def load(target, stubs=None, real=(), env=None, argv=None, rows=None, stdout="", stderr="", code=0, content="", exists=True, auto_stub=True):
    """Executes the repository module at `target` with the fakes injected; returns the module."""
    _reset()
    for name in _loaded_names:
        sys.modules.pop(name, None)
    del _loaded_names[:]
    _config.clear()
    _config.update({"rows": rows, "stdout": stdout, "stderr": stderr, "code": code, "content": content, "exists": exists, "auto_stub": auto_stub})
    path = target if os.path.isabs(target) else os.path.normpath(os.path.join(ROOT, target))
    if not os.path.isfile(path):
        raise HarnessAssertion("harness.load: no such repository file: %s" % target)
    _install(set(real), stubs)
    # A literal environment name the module reads but the test did not set gets a placeholder,
    # so a patch that moved one secret to os.environ does not crash every other test of the
    # same patch at import. os.environ.get() keeps its real semantics for names never read this way.
    with _real_open(path, encoding="utf-8", errors="replace") as handle:
        for name in re.findall(r"""\bos\.environ\s*\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]""", handle.read()):
            if name not in dict(env or {}) and not dict.__contains__(os.environ, name):
                dict.__setitem__(os.environ, name, "mitig8it-unset-" + name)
    for key, value in dict(env or {}).items():
        dict.__setitem__(os.environ, key, str(value))
    # Module-scope code may read its input from the command line, which is the only way a test
    # can set it: the sink runs on import, before anything else can be called.
    sys.argv = [str(item) for item in argv] if argv else list(_real_argv)
    for directory in (os.path.dirname(path), ROOT):
        if directory not in sys.path:
            sys.path.insert(0, directory)
    before = set(sys.modules)
    name = _package_name(path)
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        _loaded_names.extend(sorted((set(sys.modules) - before) | {name}))
    return module


def _package_name(path):
    """The dotted name to load `path` under, registering the packages its own imports need.

    A module inside a package uses a relative import to reach its siblings, and Python resolves
    that against `__package__`. Loaded by its bare basename it has none, so the module did not
    load at all, which is a proof that cannot fail on the vulnerable code any more than it can
    pass on the repaired one. The directories between the repository root and the module are
    registered as packages here, with `__path__` set so the relative import resolves.

    Each one is a synthetic package: its own `__init__.py` is deliberately not executed, because
    the harness loads exactly the module the proof names and nothing else. A directory whose
    name is not an identifier has no dotted name, so that module keeps the bare one.
    """
    stem = os.path.splitext(os.path.basename(path))[0]
    relative = os.path.relpath(os.path.dirname(path), ROOT)
    parts = [] if relative in (".", "") else relative.split(os.sep)
    if not parts or not all(part.isidentifier() for part in parts) or not stem.isidentifier():
        return stem
    directory = ROOT
    for index, part in enumerate(parts):
        directory = os.path.join(directory, part)
        dotted = ".".join(parts[: index + 1])
        existing = sys.modules.get(dotted)
        if existing is None or not hasattr(existing, "__path__"):
            package = types.ModuleType(dotted)
            package.__path__ = [directory]
            package.__package__ = dotted
            sys.modules[dotted] = package
    return ".".join(parts + [stem])


class Call:
    def __init__(self, value=None, error=None):
        self.value, self.error = value, error

    @property
    def ok(self):
        return self.error is None

    def raised(self, exc_type=Exception):
        return isinstance(self.error, exc_type)


def call(fn, *args, **kwargs):
    """Calls a plain function; never raises. Returns Call(value, error)."""
    try:
        return Call(value=fn(*args, **kwargs))
    except Exception as error:  # noqa: BLE001 - the test inspects the error
        # Named on stderr so a failing assertion's output tail says what actually happened.
        sys.stderr.write("harness: call(%s) raised %s: %s\n" % (getattr(fn, "__name__", fn), type(error).__name__, error))
        return Call(error=error)


# --- assertions -------------------------------------------------------------------------------
def assert_true(condition, message="assertion failed"):
    if not condition:
        fail(message)


def assert_equal(actual, expected, message="values differ"):
    if actual != expected:
        fail(message, {"actual": actual, "expected": expected})


def assert_includes(text, needle, message=None):
    if str(needle) not in str(text):
        fail(message or "expected text to include %r" % needle, text)


def assert_not_includes(text, needle, message=None):
    if str(needle) in str(text):
        fail(message or "expected text not to include %r" % needle, text)


def _flatten(value):
    if isinstance(value, dict):
        return [item for inner in value.values() for item in _flatten(inner)]
    if isinstance(value, (list, tuple, set)):
        return [item for inner in value for item in _flatten(inner)]
    return [value]


def assert_param(query, payload, message=None):
    """The recorded query keeps the payload out of its SQL text and passes it as a bound parameter."""
    if not query:
        fail(message or "no query was recorded")
    if str(payload) in query["sql"]:
        fail(message or "the injected input %r reached the SQL text" % payload, query["sql"])
    if not any(str(item) == str(payload) or str(payload) in str(item) for item in _flatten(query.get("params"))):
        fail(message or "expected the injected input %r to be a bound parameter" % payload, query.get("params"))


def assert_argv(call_entry, payload, message=None):
    """The recorded process ran with an argv list, no shell, and the payload as its own element."""
    if not call_entry:
        fail(message or "no process call was recorded")
    if call_entry.get("shell") or call_entry.get("args") is None:
        fail(message or "command ran through a shell: %s" % call_entry.get("command"))
    if str(payload) not in call_entry["args"]:
        fail(message or "expected the injected input %r to be its own argv element" % payload, call_entry["args"])


def _escapes(payload):
    for value in (str(payload), urllib.parse.unquote(str(payload))):
        if ".." in value.replace("\\", "/").split("/") or os.path.isabs(value):
            return True
    return False


def assert_inside(reads, base, payload=None, message=None):
    """Every recorded read stays strictly under `base`; a traversal payload must have read nothing."""
    entries = [item for item in (reads if isinstance(reads, list) else [reads]) if item is not None]
    root = os.path.realpath(str(base))
    if payload is not None and _escapes(payload) and entries:
        fail(message or "expected %r to be rejected before any file access" % str(payload), [item["path"] if isinstance(item, dict) else str(item) for item in entries])
    for item in entries:
        resolved = item["resolved"] if isinstance(item, dict) else os.path.realpath(str(item))
        relative = os.path.relpath(resolved, root)
        if relative == "." or relative.startswith("..") or os.path.isabs(relative):
            fail(message or "expected %s to stay under %s" % (resolved, base))


def assert_env_read(name, message=None):
    if name not in env.reads:
        fail(message or "expected the module to read environment variable %r" % name, env.reads)


def assert_not_in_source(module, literal, message=None):
    """The module carries the literal neither in its source text nor in a module-level value."""
    with _real_open(module.__file__, encoding="utf-8", errors="replace") as handle:
        if str(literal) in handle.read():
            fail(message or "the source still contains %r" % literal)
    for key, value in vars(module).items():
        if not key.startswith("__") and isinstance(value, (str, bytes)) and str(literal) in str(value):
            fail(message or "module attribute %s still carries %r" % (key, literal))


def assert_no_commands(message=None):
    if subprocess.calls:
        fail(message or "expected no process to run", [item["command"] for item in subprocess.calls])


def run(body):
    """Runs one test body: exit 0 when it returns, exit 1 with the error otherwise."""
    try:
        result = body()
        if inspect.iscoroutine(result):
            import asyncio

            asyncio.run(result)
    except SystemExit:
        raise
    except BaseException:  # noqa: BLE001 - every failure is reported the same way
        sys.stderr.write("harness: " + "".join(traceback.format_exc()))
        sys.stderr.flush()
        sys.exit(1)
    sys.stdout.write("harness: ok\n")
    sys.stdout.flush()
    sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("usage: python3 .mitig8it/harness.py <test.py>\n")
        sys.exit(2)
    sys.modules["harness"] = sys.modules[__name__]
    _test = os.path.abspath(sys.argv[1])
    sys.argv = sys.argv[1:]
    sys.path.insert(0, os.path.dirname(_test))
    import runpy

    runpy.run_path(_test, run_name="__main__")
