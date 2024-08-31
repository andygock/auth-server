const express = require('express');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const nocache = require('nocache');

const app = express();

// rate limiter used on auth attempts
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // limit each IP to 15 requests per windowMs
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
const expiryDays = process.env.AUTH_EXPIRY_DAYS || 7;
const cookieSecure =
  'AUTH_COOKIE_SECURE' in process.env
    ? process.env.AUTH_COOKIE_SECURE === 'true'
    : true;

// actual cookie, if there is a realm is cookieName_realm
const cookieName = process.env.AUTH_COOKIE_NAME || 'authToken';

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

const cookieNameRealm = (realm) => `${cookieName}_${encodeURIComponent(realm)}`;

// default auth function
// can be customised by defining one in auth.js, e.g use custom back end database
// using single password for the time being, but this could query a database etc
let checkAuth = (user, pass, realm) => {
  console.log('checkAuth()', user, pass, realm);

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
  customCheckAuth = require('./auth.js');
  if (typeof customCheckAuth === 'function') checkAuth = customCheckAuth;
} catch (ex) {}

if (!tokenSecret) {
  console.error(
    'Misconfigured server. Environment variable AUTH_TOKEN_SECRET is not configured'
  );
  process.exit(1);
}

// middleware to check auth status
const jwtVerify = (req, res, next) => {
  // get token from cookies
  const token = req.cookies[cookieName];

  // check for missing token
  if (!token) return next();

  jwt.verify(token, tokenSecret, (err, decoded) => {
    if (err) {
      // e.g malformed token, bad signature etc - clear the cookie also
      console.log(err);
      res.clearCookie(cookieName);
      return res.status(403).send(err);
    }

    req.user = decoded.user || null;
    next();
  });
};

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
  return res.render('logged-in', {
    useUsername: process.env.AUTH_USE_USERNAME || false,
    user: req.user || null,
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
    useUsername: process.env.AUTH_USE_USERNAME || false,
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
    const payload = { user: req.user, realm };
    const token = jwt.sign(payload, tokenSecret, {
      expiresIn: `${expiryDays}d`,
    });

    // set JWT as cookie, 7 day age
    res.cookie(cookieName, token, {
      httpOnly: true,
      maxAge: 1000 * 86400 * expiryDays, // milliseconds
      secure: cookieSecure,
      ...cookieOverrides,
    });

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

  if (checkAuth(username, password)) {
    // successful auth
    const user = username || defaultUser;

    // generate JWT
    const token = jwt.sign({ user, realm }, tokenSecret, {
      expiresIn: `${expiryDays}d`,
    });

    // set JWT as cookie, 7 day age
    res.cookie(cookieName, token, {
      httpOnly: true,
      maxAge: 1000 * 86400 * expiryDays, // milliseconds
      secure: cookieSecure,
      ...cookieOverrides,
    });
    return res.send({ status: 'ok' });
  }

  // failed auth
  res.status(401).send({ status: 'fail', message: 'Invalid credentials' });
});

// force logout
app.get('/logout', (req, res) => {
  res.clearCookie(cookieName);
  res.redirect('/login');
});

// endpoint called by logout page
app.post('/logout', (req, res) => {
  const options = {};
  if (cookieOverrides.path) {
    options.path = cookieOverrides.path;
  }
  if (cookieOverrides.domain) {
    options.domain = cookieOverrides.domain;
  }
  res.clearCookie(cookieName, options);
  res.sendStatus(200);
});

// default 404
app.use((req, res, next) => {
  res.status(404).send('No such page');
});

app.listen(port, () => console.log(`Listening at http://localhost:${port}`));
