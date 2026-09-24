// Session wiring in the shape the vulnerable corpus found it in: the credential is a
// property of a multi-line object literal handed straight to a middleware call, so the
// rule that matches it reports the line the call opens on, three lines above the secret.
const store = new Map();

function install(app) {
  app.use(session({
    secret: 'keyboard cat',
    resave: true,
    saveUninitialized: true,
  }));
  return app;
}

function session(options) {
  return function middleware(request) {
    const id = sign(request.id, options.secret);
    store.set(id, { resave: options.resave, saveUninitialized: options.saveUninitialized });
    return id;
  };
}

function sign(value, secret) {
  return `${value}.${Buffer.from(String(secret)).toString('base64')}`;
}

module.exports = { install, session, sign, store };
