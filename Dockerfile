FROM node:20-alpine

RUN apk update && apk upgrade

RUN mkdir -p /app/node_modules && chown -R node:node /app

WORKDIR /app

COPY --chown=node:node package.json yarn.lock ./

USER node

RUN yarn install

COPY --chown=node:node public public
COPY --chown=node:node views views
COPY --chown=node:node app.js ./

EXPOSE 3000

CMD ["/bin/sh", "-c", "npm start 2>&1 | tee log.txt"]
