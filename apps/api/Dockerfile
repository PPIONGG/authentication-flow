FROM node:22-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first (better layer caching)
COPY package.json package-lock.json* ./
RUN npm install

# Copy prisma schema + config, then generate the client into src/generated/prisma.
# prisma.config.ts requires DATABASE_URL even for `generate`, but generate never
# connects — so a throwaway URL satisfies it at build time. The real DATABASE_URL
# is injected at runtime via docker-compose `environment:`.
COPY prisma ./prisma
COPY prisma.config.ts ./
RUN DATABASE_URL="postgresql://build:build@localhost:5432/build" npx prisma generate

# Copy the rest of the source
COPY . .

RUN chmod +x docker-entrypoint.sh

EXPOSE 3000

ENTRYPOINT ["./docker-entrypoint.sh"]
