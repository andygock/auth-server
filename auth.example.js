/**
 * Example authorisation routine, rename it to 'auth.js' to use it
 */

const dotenv = require('dotenv');

// read .env and store in process.env
dotenv.config();

const authPassword = process.env.AUTH_PASSWORD;

// using single password for the time being, but this could query a database etc
const checkAuth = (user, pass, realm) => {
  if (!authPassword) {
    console.error(
      'Misconfigured server. Environment variable AUTH_PASSWORD is not configured'
    );
    process.exit(1);
  }

  if (pass === authPassword) return true;
  return false;
};

module.exports = checkAuth;
