FROM node:lts

#RUN npm install -g npm@latest

#> Set default args and environment.
ARG NRD_REGISTRY="https://git02.int.nsc.ag/api/v4/projects/1015/packages/npm/"
ARG NPM_TOKEN="[...]"
ENV NODE_ENV="production"

#> Create the working directory for the GAIABox application.
RUN mkdir -p /opt/gbx
WORKDIR /opt/gbx

#> Configure npm with the custom registry.
#RUN npm config set -- ${NRD_REGISTRY#http*:}:_authToken=${NRD_TOKEN}
#RUN npm config set @nrd:registry=${NRD_REGISTRY}
#RUN cat ~/.npmrc

#> Create a .npmrc file with the nrd registry and token.
RUN echo "@nrd:registry=${NRD_REGISTRY}\n${NRD_REGISTRY#http*:}:_authToken=${NPM_TOKEN}" >> .npmrc
#RUN cat .npmrc

#> Install the application via npm.
RUN npm install @nrd/fua.app.daps

#> DEBUG
#RUN ls -a "node_modules/.bin"
#RUN ls -a "node_modules/@nrd/fua.app.daps"
#RUN cat node_modules/.bin/fua.app.daps

#> Clean up the created .npmrc file, because it contains sensitive information.
RUN rm .npmrc

#> TODO fix the bin executable
#ENTRYPOINT ["fua.app.daps"]
#ENTRYPOINT ["@nrd/fua.app.daps"]

EXPOSE 8083

WORKDIR /opt/gbx/node_modules/@nrd/fua.app.daps
ENTRYPOINT ["npm", "start"]
