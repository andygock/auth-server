const express = require('express');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const nocache = require('nocache');
const path = require('path');

const app = express();

const parseBooleanEnv = (value, defaultValue = false) => {
  if (value === undefined) {
    return defaultValue;
  }

  return ['true', '1', 'yes', 'on'].includes(String(value).toLowerCase());
};

const isLoopbackAddress = (address) => {
  return (
    address === '127.0.0.1' ||
    address === '::1' ||
    address === '::ffff:127.0.0.1'
  );
};

const getClientAddress = (req) => {
  const remoteAddress = req.socket.remoteAddress;
  const originalRemoteAddr = req.headers['x-original-remote-addr'];

  if (isLoopbackAddress(remoteAddress) && originalRemoteAddr) {
    return originalRemoteAddr;
  }

  return req.ip;
};

const getJwtSignOptions = (realm) => ({
  algorithm: 'HS256',
  expiresIn: `${expiryDays}d`,
  issuer: 'auth-server',
  audience: realm || 'default',
});

const getJwtVerifyOptions = (realm) => ({
  algorithms: ['HS256'],
  issuer: 'auth-server',
  audience: realm || 'default',
});

const getAuthCookieOptions = () => ({
  httpOnly: true,
  maxAge: 1000 * 86400 * expiryDays,
  sameSite: 'lax',
  secure: cookieSecure,
  ...cookieOverrides,
});

const getClearCookieOptions = () => {
  const { domain, path, sameSite, secure } = getAuthCookieOptions();
  return { domain, path, sameSite, secure };
};

// rate limiter used on auth attempts
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // limit each IP to 15 requests per windowMs
  keyGenerator: (req) => getClientAddress(req),
  message: {
    status: 'fail',
    message: 'Too many requests, please try again later',
  },
});

// read .env and store in process.env
dotenv.config();

// config vars
const port = process.env.AUTH_PORT || 3000;
const tokenSecret = process.env.AUTH_TOKEN_SECRET;
const defaultUser = 'user'; // default user when no username supplied
const expiryDays = Number.parseInt(process.env.AUTH_EXPIRY_DAYS || '7', 10);
const cookieSecure = parseBooleanEnv(process.env.AUTH_COOKIE_SECURE, true);
const useUsername = parseBooleanEnv(process.env.AUTH_USE_USERNAME, false);
const visitLinkUrl = process.env.AUTH_VISIT_LINK_URL || null;

// actual cookie, if there is a realm is cookieName_realm
const cookieName = process.env.AUTH_COOKIE_NAME || 'authToken';

if (!Number.isFinite(expiryDays) || expiryDays <= 0) {
  console.error(
    'Misconfigured server. Environment variable AUTH_EXPIRY_DAYS must be a positive integer'
  );
  process.exit(1);
}

let cookieOverrides = {};
try {
  if (process.env.AUTH_COOKIE_OVERRIDES) {
    const parsed = JSON.parse(process.env.AUTH_COOKIE_OVERRIDES);
    for (const k of Object.keys(parsed)) {
      cookieOverrides[k] = parsed[k];
    }
  }
} catch (e) {
  console.log(
    `Warning: Could not parse AUTH_COOKIE_OVERRIDES: ${process.env.AUTH_COOKIE_OVERRIDES}\n`
  );
  console.log(e);
  process.exit(1);
}

const cookieNameWithRealm = (realm) => {
  if (!realm) {
    return cookieName;
  }
  return `${cookieName}_${encodeURIComponent(realm)}`;
};

// default auth function
// can be customised by defining one in auth.js, e.g use custom back end database
// using single password for the time being, but this could query a database etc
let checkAuth = (user, pass, realm) => {
  // console.log('checkAuth()', user, pass, realm);

  const authPassword = process.env.AUTH_PASSWORD;
  if (!authPassword) {
    console.error(
      'Misconfigured server. Environment variable AUTH_PASSWORD is not configured'
    );
    process.exit(1);
  }

  // check for correct user password
  if (pass === authPassword) return true;
  return false;
};

// load checkAuth() if defined by user in auth.js
try {
  const customAuthPath = path.resolve(__dirname, 'auth.js');
  const customCheckAuth = require(customAuthPath);
  if (typeof customCheckAuth === 'function') checkAuth = customCheckAuth;
} catch (ex) {
  if (
    ex.code !== 'MODULE_NOT_FOUND' ||
    !ex.message.includes(path.resolve(__dirname, 'auth.js'))
  ) {
    console.error('Failed to load custom auth.js');
    console.error(ex);
    process.exit(1);
  }
}

if (!tokenSecret) {
  console.error(
    'Misconfigured server. Environment variable AUTH_TOKEN_SECRET is not configured'
  );
  process.exit(1);
}

// middleware to check auth status
const jwtVerify = (req, res, next) => {
  const realm = req.headers['x-auth-realm'];

  // get token from cookies
  const token = req.cookies[cookieNameWithRealm(realm)];

  // check for missing token
  if (!token) return next();

  jwt.verify(token, tokenSecret, getJwtVerifyOptions(realm), (err, decoded) => {
    if (err) {
      // e.g malformed token, bad signature etc - clear the cookie also
      console.log(err);
      res.clearCookie(cookieNameWithRealm(realm), getClearCookieOptions());
      return res.status(403).send(err);
    }

    if (decoded.realm !== (realm || null)) {
      res.clearCookie(cookieNameWithRealm(realm), getClearCookieOptions());
      return res.status(403).send({
        status: 'fail',
        message: 'Token realm does not match request realm',
      });
    }

    req.user = decoded.user || null;
    next();
  });
};

app.set('trust proxy', 'loopback');
app.set('view engine', 'ejs');

// logging
// https://github.com/expressjs/morgan
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('common'));
}

// serve static files in ./public
app.use(express.static('public'));

// parse cookies
app.use(cookieParser());

// parse json body
app.use(express.json());

// don't allow any form of caching, private or public
app.use(nocache());

// check for JWT cookie from requestor
// if there is a valid JWT, req.user is assigned
app.use(jwtVerify);

// we don't need a root path, direct to login interface
app.get('/', (req, res) => {
  res.redirect('/login');
});

// interface for users who are logged in
app.get('/logged-in', (req, res) => {
  if (!req.user) return res.redirect('/login');
  // redirect to AUTH_VISIT_LINK_URL if set, otherwise use X-Original-URI from login flow
  const redirectUrl = visitLinkUrl || req.query.redirect || null;
  if (redirectUrl) return res.redirect(redirectUrl);
  return res.render('logged-in', {
    useUsername,
    user: req.user || null,
    visitLinkUrl,
  });
});

// login interface
app.get('/login', (req, res) => {
  // parameters from original client request
  // these could be used for validating request
  const requestUri = req.headers['x-original-uri'];
  const remoteAddr = req.headers['x-original-remote-addr'];
  const host = req.headers['x-original-host'];
  const realm = req.headers['x-auth-realm'];

  // check if user is already logged in
  if (req.user) return res.redirect('/logged-in');

  // user not logged in, show login interface
  return res.render('login', {
    referer: requestUri ? `${host}/${requestUri}` : '/',
    useUsername,
  });
});

// endpoint called by NGINX sub request
// expect JWT in cookieName
app.get('/auth', (req, res, next) => {
  // parameters from original client request
  // these could be used for validating request
  const requestUri = req.headers['x-original-uri'];
  const remoteAddr = req.headers['x-original-remote-addr'];
  const host = req.headers['x-original-host'];
  const realm = req.headers['x-auth-realm'];

  if (req.user) {
    // user is already authenticated, refresh cookie and regenerate JWT
    const payload = { user: req.user, realm: realm || null };
    const token = jwt.sign(payload, tokenSecret, getJwtSignOptions(realm));

    // set JWT as cookie, 7 day age
    res.cookie(cookieNameWithRealm(realm), token, getAuthCookieOptions());

    return res.sendStatus(200);
  } else {
    // not authenticated
    return res.sendStatus(401);
  }
});

// endpoint called by login page, username and password posted as JSON body
app.post('/login', apiLimiter, (req, res) => {
  // console.log('/login', req.realm);

  const { username, password } = req.body;
  const realm = req.headers['x-auth-realm'];

  if (checkAuth(username, password, realm)) {
    // successful auth
    const user = username || defaultUser;

    // generate JWT
    const token = jwt.sign(
      { user, realm: realm || null },
      tokenSecret,
      getJwtSignOptions(realm)
    );

    // set JWT as cookie, 7 day age
    res.cookie(cookieNameWithRealm(realm), token, getAuthCookieOptions());
    return res.send({ status: 'ok' });
  }

  // failed auth
  res.status(401).send({ status: 'fail', message: 'Invalid credentials' });
});

// force logout
app.get('/logout', (req, res) => {
  const realm = req.headers['x-auth-realm'];

  // Disable caching
  res.set(
    'Cache-Control',
    'no-store, no-cache, must-revalidate, proxy-revalidate'
  );
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.set('Surrogate-Control', 'no-store');

  res.clearCookie(cookieNameWithRealm(realm), getClearCookieOptions());
  res.redirect('/login');
});

// endpoint called by logout page
app.post('/logout', (req, res) => {
  const realm = req.headers['x-auth-realm'];

  // Disable caching
  res.set(
    'Cache-Control',
    'no-store, no-cache, must-revalidate, proxy-revalidate'
  );
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.set('Surrogate-Control', 'no-store');

  res.clearCookie(cookieNameWithRealm(realm), getClearCookieOptions());
  res.sendStatus(200);
});

// default 404
app.use((req, res, next) => {
  res.status(404).send('No such page');
});

app.listen(port, () => console.log(`Listening at http://localhost:${port}`));
