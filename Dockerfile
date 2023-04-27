FROM node:lts AS builder

# 1. Set default arguments and environment for the builder.

ARG NRD_REGISTRY="https://git02.int.nsc.ag/api/v4/projects/1015/packages/npm/"
ARG NPM_TOKEN="[...]"

ENV NODE_ENV="production"

# 2. Create the working directory for the application and the necessary files for the installation, e.g. npmrc file.

RUN mkdir -p /opt/gbx
WORKDIR /opt/gbx
RUN echo "@nrd:registry=${NRD_REGISTRY}\n${NRD_REGISTRY#http*:}:_authToken=${NPM_TOKEN}" >> .npmrc

# 3. Install the application via npm.

RUN npm install @nrd/fua.app.daps

# 4. use lts-alpine as runner to reduce image size.

FROM node:lts-alpine AS runner

# 5. Set default arguments and environment for the runner.

ENV NODE_ENV="production"
ENV SERVER_HOST="localhost"
ENV SERVER_PORT="8080"

# 6. Copy application from builder and setup environment.

RUN mkdir -p /opt/gbx
COPY --from=builder /opt/gbx/node_modules /opt/gbx/node_modules
ENV PATH="$PATH:/opt/gbx/node_modules/.bin"

# 7. Define image setup and application entrypoint.

EXPOSE $SERVER_PORT

HEALTHCHECK --start-period=10s --interval=5m --timeout=10s --retries=3 \
    CMD curl -f https://${SERVER_HOST}:${SERVER_PORT}/ || exit 1

ENTRYPOINT fua.app.daps
