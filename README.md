# auth-server

A very simple standalone authentication server Express app.

It can be used for protecting web sites with NGINX subrequest authentication.

- Use `auth_request /auth` in [NGINX conf](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/).
- When user requests protected area, NGINX makes an internal request to `/auth`. If 201 is returned, protected contents are served. Anything else, NGINX responds with 401.
- `/auth` is reverse proxied to Express app [auth-server](https://github.com/andygock/auth-server) which handles authentication. Cookies are passed on as well, so the auth server can check for a [JWT](https://jwt.io/).
- Auth server sets httpOnly cookie containing a JWT.
- JWT updated with new expiry each time a user visits protected area.
- Default rate limit of 15 `/login` requests every 15 minutes.

## How to use

Refer to this tutorial on my blog:

<https://gock.net/blog/2020/nginx-subrequest-authentication-server/>

## Configure `.env`

- `AUTH_PORT` -  Listening port of application (default: 3000)
- `AUTH_PASSWORD` - Authentication password
- `AUTH_TOKEN_SECRET` - [JWT secret](https://en.wikipedia.org/wiki/JSON_Web_Token#Structure)
- `AUTH_COOKIE_SECURE` - Secure attribute on authentication cookie sent from server. Set to `true` to enable, or if `AUTH_COOKIE_SECURE` is missing, defaults to `true`.

Refer to [dotenv documentation](https://github.com/motdotla/dotenv#readme) for formatting.

You can define a custom auth routine in `auth.js`. See `auth.example.js` for an example. If you don't configure a `auth.js` it will use default simgple `AUTH_PASSWORD` password based authentication.

## Development

Install [nodemon](https://nodemon.io/) globally.

Install dependencies

    npm install

Start dev server

    npm start

I developed this using `pnpm` so you can use that instead of `npm` if you prefer.

    pnpm install
    pnpm start

Be aware that the authentication cookie used by default uses the [secure attribute](https://en.wikipedia.org/wiki/Secure_cookie) thus the demo will only work when connecting via

- HTTPS to a non-local IP address, or
- HTTPS to a hostname other than "localhost", or
- HTTP/HTTPS to localhost.

## Production

Install with [pm2](https://pm2.keymetrics.io/)

    pm2 start ./app.js --name auth

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
}

# these are handled by the proxy as part of the auth routines
location ~ ^/(login|logged-in|logout)$ {
    proxy_pass http://localhost:3000;
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Remote-Addr $remote_addr;
    proxy_set_header X-Original-Host $host;
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

- [Skeleton CSS](https://github.com/dhg/Skeleton)
- [NGINX sub request authentication](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/)
- [Using JWTs with NodeJS tutorial](https://www.digitalocean.com/community/tutorials/nodejs-jwt-expressjs)
- [jsonwebtoken node module](https://github.com/auth0/node-jsonwebtoken)
