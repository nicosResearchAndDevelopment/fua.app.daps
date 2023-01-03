FROM node:lts

ARG NRD_REGISTRY="https://git02.int.nsc.ag/api/v4/projects/1015/packages/npm/"
ARG NRD_TOKEN="[...]"

ENV NODE_ENV="production"

RUN mkdir -p /opt/gbx
WORKDIR /opt/gbx

RUN echo "\
    @nrd:registry = ${NRD_REGISTRY} \n\
    ${NRD_REGISTRY#http*:}:_authToken = ${NRD_TOKEN} \n\
    " >> .npmrc

RUN cat .npmrc

RUN npm install @nrd/fua.app.daps --production

ENTRYPOINT ["@nrd/fua.app.daps"]
