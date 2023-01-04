FROM node:lts

# 1. Set default arguments and environment.

ARG NRD_REGISTRY="https://git02.int.nsc.ag/api/v4/projects/1015/packages/npm/"
ARG NPM_TOKEN="[...]"

ENV NODE_ENV="production"
ENV SERVER_HOST="localhost"
ENV SERVER_PORT="8080"

# 2. Create the working directory for the application.

RUN mkdir -p /opt/gbx
WORKDIR /opt/gbx

# 3. Create necessary files for the installation, e.g. npmrc file.

RUN echo "@nrd:registry=${NRD_REGISTRY}\n${NRD_REGISTRY#http*:}:_authToken=${NPM_TOKEN}" >> .npmrc

# 4. Install the application via npm and do any necessary setup.

RUN npm install @nrd/fua.app.daps
ENV PATH="$PATH:/opt/gbx/node_modules/.bin"

# 5. Clean up unnecessary or sensitive files, e.g. npmrc file.

RUN rm .npmrc

# 6. Define image setup and application entrypoint.

EXPOSE $SERVER_PORT
ENTRYPOINT fua.app.daps
