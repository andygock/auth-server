# auth-server

A very simple standalone authentication server Express app. Requires Node.js 18.11.0 or later.

It can be used for protecting web sites with NGINX subrequest authentication.

- Use `auth_request /auth` in [NGINX conf](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/).
- When user requests protected area, NGINX makes an internal request to `/auth`. If 201 is returned, protected contents are served. Anything else, NGINX responds with 401.
- `/auth` is reverse proxied to Express app [auth-server](https://github.com/andygock/auth-server) which handles authentication. Cookies are passed on as well, so the auth server can check for a [JWT](https://jwt.io/).
- Auth server sets httpOnly cookie containing a JWT.
- JWT updated with new expiry each time a user visits protected area.
- Configurable per-IP rate limiter on `/login` (default: 20 requests per 15 minutes) and global rate limiter on all routes (default: 100 requests per minute).

## How to use

Refer to this tutorial on my blog:

<https://gock.net/blog/2020/nginx-subrequest-authentication-server/>

## Configure `.env`

- `AUTH_PORT` - Listening port of application (default: 3000)
- `AUTH_PASSWORD` - Authentication password
- `AUTH_TOKEN_SECRET` - [JWT secret](https://en.wikipedia.org/wiki/JSON_Web_Token#Structure)
- `AUTH_COOKIE_SECURE` - Secure attribute on authentication cookie sent from server. Parsed as a boolean. If `AUTH_COOKIE_SECURE` is missing, it defaults to `true`.
- `AUTH_COOKIE_OVERRIDES` - Optional JSON string which is added to the `authToken` cookie, in addition to `httpOnly`, `secure`, `sameSite=lax` and `maxAge`.
- `AUTH_EXPIRY_DAYS` - Optional number of days before JWT expires (default: 7)
- `AUTH_COOKIE_NAME` - Optional name of the cookie prefix used for the JWT (default: `authToken`)
- `AUTH_USE_USERNAME` - Optional boolean to use a username too (default: `false`)
- `AUTH_VISIT_LINK_URL` - Optional URL for the "Visit" link shown on the logged-in page. When set, the user is immediately redirected here after login (server-side). When not set, the user is redirected back to the original URL they were trying to access (from the NGINX `X-Original-URI` header), or shown the logged-in page if no referrer is available.
- `AUTH_LOGIN_RATE_LIMIT_WINDOW_MIN` - Per-IP rate limit time window in minutes for `/login` attempts (default: `15`)
- `AUTH_LOGIN_RATE_LIMIT_MAX` - Maximum number of `/login` attempts per IP within the time window (default: `20`)
- `AUTH_GLOBAL_RATE_LIMIT_WINDOW_MIN` - Global rate limit time window in minutes applied to all routes (default: `1`)
- `AUTH_GLOBAL_RATE_LIMIT_MAX` - Maximum number of all requests (across all IPs) within the global time window (default: `100`)

Refer to [dotenv documentation](https://github.com/motdotla/dotenv#readme) for formatting.

You can define a custom auth routine in `auth.js`. See `auth.example.js` for an example. If you don't configure a `auth.js` it will use default simple `AUTH_PASSWORD` password based authentication.

## Development

I use [pnpm](https://pnpm.io/) for development, but you can also use `npm` or `yarn` if you prefer.

Install dependencies

    pnpm install

Start dev server with Node.js built-in file watcher

    pnpm dev

Be aware that the authentication cookie used by default uses the [secure attribute](https://en.wikipedia.org/wiki/Secure_cookie) thus the demo will only work when connecting via

- HTTPS to a non-local IP address, or
- HTTPS to a hostname other than "localhost", or
- HTTP/HTTPS to localhost.

## Production

Start with

    pnpm start

### PM2

Install with [pm2](https://pm2.keymetrics.io/)

    NODE_ENV=production pm2 start ./app.js --name auth

### Docker

```sh
sudo docker build -t auth-server .
sudo docker run -it -p 3000:3000 -e AUTH_PASSWORD=test -e AUTH_TOKEN_SECRET=verysecret auth-server
```

This server expects `X-Original-Remote-Addr` to be set by a trusted loopback proxy such as local NGINX. The bundled rate limiter only uses that header when the direct peer is a loopback address.

## Example NGINX conf

Use the following in our NGINX server conf. You should change the port number (default of `3000`) to match the port number you are running the auth server on.

```txt
# optional:
# internal redirect to /login if there is a auth failure, delete or comment this out if you don't want this behaviour and just show a generic 401 error
error_page 401 /login;

location / {
    auth_request /auth;

    # pass Set-Cookie headers from the subrequest response back to requestor
    auth_request_set $auth_cookie $upstream_http_set_cookie;
    add_header Set-Cookie $auth_cookie;

    auth_request_set $auth_status $upstream_status;

    try_files $uri $uri/ /index.html;
}

location = /auth {
    # internaly only, /auth can not be accessed from outside
    internal;

    # internal proxy to auth-server running on port 3000, responses expected from proxy:
    #   2xx response = access allowed via auth_request
    #   401 or 403 response = access denied via auth_request
    #   anything else = error
    proxy_pass http://localhost:3000;

    # don't pass request body to proxied server, we only need the headers which are passed on by default
    proxy_pass_request_body off;

    # there is no content length since we stripped the request body
    proxy_set_header Content-Length "";

    # let proxy server know more details of request
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Remote-Addr $remote_addr;
    proxy_set_header X-Original-Host $host;

    # optional realm header, allows to use the same auth server for multiple sites
    proxy_set_header X-Auth-Realm "myrealm";
}

# these are handled by the proxy as part of the auth routines
location ~ ^/(login|logged-in|logout)$ {
    proxy_pass http://localhost:3000;
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Remote-Addr $remote_addr;
    proxy_set_header X-Original-Host $host;

    # optional realm header, allows to use the same auth server for multiple sites
    proxy_set_header X-Auth-Realm "myrealm";
}

# this CSS is used by the three requests above and is served by the proxy
location ~* ^/(auth_style\.css|auth_padlock\.svg)$ {
    proxy_pass http://localhost:3000;
}

# optional location block
# if you have other location blocks, be sure to add auth_request there too otherwise these requests won't get protected, for example
location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
    expires 90d;
    log_not_found off;
    auth_request /auth;
}
```

## References

- [NGINX sub request authentication](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/)
- [Using JWTs with NodeJS tutorial](https://www.digitalocean.com/community/tutorials/nodejs-jwt-expressjs)
- [jsonwebtoken node module](https://github.com/auth0/node-jsonwebtoken)
