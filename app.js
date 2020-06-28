const express = require('express');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');

const app = express();

// read .env and store in process.env
dotenv.config();

// config vars
const port = process.env.AUTH_PORT || 3000;
const authPassword = process.env.AUTH_PASSWORD;
const tokenSecret = process.env.AUTH_TOKEN_SECRET;
const defaultUser = 'user'; // default user when no username supplied
const expiryDays = 7;

if (!authPassword || !tokenSecret) {
  console.error(
    'Misconfigured server. Environment variables AUTH_PASSWORD and/or AUTH_TOKEN_SECRET are not configured'
  );
  process.exit(1);
}

// middleware to check auth status
const jwtVerify = (req, res, next) => {
  // get token from cookies
  const token = req.cookies.authToken;

  // check for missing token
  if (!token) return next();

  jwt.verify(token, tokenSecret, (err, decoded) => {
    if (err) {
      // e.g malformed token, bad signature etc - clear the cookie also
      console.log(err);
      res.clearCookie('authToken');
      return res.status(403).send(err);
    }

    req.user = decoded.user || null;
    next();
  });
};

// using single password for the time being, but this could query a database etc
const checkAuth = (user, pass) => {
  if (pass === authPassword) return true;
  return false;
};

app.set('view engine', 'ejs');

// logging
app.use(morgan('dev'));

// serve static files in ./public
app.use(express.static('public'));

// parse cookies
app.use(cookieParser());

// parse json body
app.use(express.json());

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
  return res.render('logged-in', { user: req.user || null });
});

// login interface
app.get('/login', (req, res) => {
  if (req.user) return res.redirect('/logged-in');
  return res.render('login');
});

// endpoint called by NGINX sub request
// expect JWT in cookie 'authToken'
app.get('/auth', (req, res, next) => {
  if (req.user) {
    // user is authenticated, refresh cookie

    // generate JWT
    const token = jwt.sign({ user: req.user }, tokenSecret, {
      expiresIn: `${expiryDays}d`,
    });

    // set JWT as cookie, 7 day age
    res.cookie('authToken', token, {
      httpOnly: true,
      maxAge: 1000 * 86400 * expiryDays, // milliseconds
      secure: true,
    });

    return res.sendStatus(200);
  } else {
    // not authenticated
    return res.sendStatus(401);
  }
});

// endpoint called by login page, username and password posted as JSON body
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (checkAuth(username, password)) {
    // successful auth
    const user = username || defaultUser;

    // generate JWT
    const token = jwt.sign({ user }, tokenSecret, {
      expiresIn: `${expiryDays}d`,
    });

    // set JWT as cookie, 7 day age
    res.cookie('authToken', token, {
      httpOnly: true,
      maxAge: 1000 * 86400 * expiryDays, // milliseconds
      secure: true,
    });
    return res.json({ status: 'ok' });
  }

  // failed auth
  res.sendStatus(401);
});

// force logout
app.get('/logout', (req, res) => {
  res.clearCookie('authToken');
  res.redirect('/login');
});

// endpoint called by logout page
app.post('/logout', (req, res) => {
  res.clearCookie('authToken');
  res.sendStatus(200);
});

// default 404
app.use((req, res, next) => {
  res.status(404).send('No such page');
});

app.listen(port, () => console.log(`Listening at http://localhost:${port}`));
