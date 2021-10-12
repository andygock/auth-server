# auth-server

A very simple standalone authentication server Express app.

It can be used for protecting web sites with NGINX subrequest authentication.

- Use `auth_request /auth` in [NGINX conf](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/).
- When user requests protected area, NGINX makes an internal request to `/auth`. If 201 is returned, protected contents are served. Anything else, NGINX responds with 401.
- `/auth` is reverse proxied to Express app [auth-server](https://github.com/andygock/auth-server) which handles authentication. Cookies are passed on as well, so the auth server can check for a [JWT](https://jwt.io/).
- Auth server sets httpOnly cookie containing a JWT.
- JWT updated with new expiry each time a user visits protected area.

## How to use

Refer to this tutorial on my blog:

<https://gock.net/blog/2020/nginx-subrequest-authentication-server/>

## Configure `.env`

- `AUTH_PORT` -  Listening port of application (default: 3000)
- `AUTH_PASSWORD` - Authentication password
- `AUTH_TOKEN_SECRET` - [JWT secret](https://en.wikipedia.org/wiki/JSON_Web_Token#Structure)
- `AUTH_COOKIE_SECURE` - Secure attribute on authentication cookie sent from server. Set to `true` to enable, or if `AUTH_COOKIE_SECURE` is missing, defaults to `true`.

Refer to [dotenv documentation](https://github.com/motdotla/dotenv#readme) for formatting.

## Development

Install [nodemon](https://nodemon.io/) globally.

Install dependencies

    yarn

Start dev server

    yarn start

## Production

Install with [pm2](https://pm2.keymetrics.io/)

    pm2 start ./app.js --name auth

## Example NGINX conf

```txt
location / {
    auth_request /auth;
    auth_request_set $auth_cookie $upstream_http_set_cookie;
    add_header Set-Cookie $auth_cookie;
    try_files $uri $uri/ /index.html;
}

location = /auth {
    internal;
    proxy_pass http://localhost:3003;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Remote-Addr $remote_addr;
    proxy_set_header X-Original-Host $host;
}

location ~ ^/(login|logged-in|logout)$ {
    proxy_pass http://localhost:3003;
}
```

## References

- [Skeleton CSS](https://github.com/dhg/Skeleton)
- [NGINX sub request authentication](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/)
- [Using JWTs with NodeJS tutorial](https://www.digitalocean.com/community/tutorials/nodejs-jwt-expressjs)
- [jsonwebtoken node module](https://github.com/auth0/node-jsonwebtoken)
