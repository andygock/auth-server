FROM node:20-alpine

RUN apk update && apk upgrade
RUN corepack enable

RUN mkdir -p /app/node_modules && chown -R node:node /app

WORKDIR /app

COPY --chown=node:node . .

USER node

RUN if command -v pnpm >/dev/null 2>&1; then \
  pnpm install --frozen-lockfile --prod; \
else \
  npm install --production --omit=dev; \
fi

EXPOSE 3000

CMD ["sh", "-c", "if command -v pnpm >/dev/null 2>&1; then pnpm start; else npm start; fi"]
