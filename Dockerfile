FROM node:lts

#RUN npm install -g npm@latest

ARG NRD_REGISTRY="https://git02.int.nsc.ag/api/v4/projects/1015/packages/npm/"
ARG NRD_TOKEN="[...]"

ENV NODE_ENV="production"

RUN mkdir -p /opt/gbx
WORKDIR /opt/gbx

# create a .npmrc file with the nrd registry and token
#RUN echo "{}" >> package.json
#RUN echo "@nrd:registry=${NRD_REGISTRY}\n${NRD_REGISTRY#http*:}:_authToken=${NRD_TOKEN}" >> .npmrc
#RUN cat .npmrc
RUN npm config set -- ${NRD_REGISTRY#http*:}:_authToken=${NRD_TOKEN}
RUN npm config set @nrd:registry=${NRD_REGISTRY}
RUN cat ~/.npmrc

RUN npm install @nrd/fua.app.daps
#RUN npm install @nrd/fua.app.daps --production
#RUN npm install @nrd/fua.app.daps --omit=dev
ENTRYPOINT ["@nrd/fua.app.daps"]

#COPY ./cert ./cert
#COPY ./data ./data
#COPY ./src ./src
#COPY ./test ./test
#COPY ./package.json ./package.json
#RUN npm install
#RUN npm test
#ENTRYPOINT ["npm", "start"]
