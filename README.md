# auth

A very simple standalone authentication server. Designed to be used with [NGINX sub request authentication](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/)

## Configure `.env`

- `AUTH_PORT` -  listening port of application
- `AUTH_PASSWORD` - authentication password
- `AUTH_TOKEN_SECRET` - [JWT secret](https://en.wikipedia.org/wiki/JSON_Web_Token#Structure)

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
