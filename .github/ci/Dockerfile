FROM node@sha256:51b1100cc2a83d370c6a60952e3f2989c8a43159d0e38586e090f3b3326efefd
WORKDIR /tooling
COPY .github/ci/package.json .github/ci/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund && npm audit --json
WORKDIR /source
COPY package.json ./
COPY lib ./lib
COPY tests ./tests
COPY .github/ci ./.github/ci
USER 10001:10001
ENV NODE_ENV=test
