FROM alpine:3.22

ARG TARGETARCH

RUN apk update && \
    apk upgrade --no-cache

RUN apk add --no-cache kubectl curl jq openssl

COPY --chmod=755 target/newrelic-auth-cli-${TARGETARCH} /bin/newrelic-auth-cli

RUN mkdir /gen-folder && chown nobody:nogroup /gen-folder

USER nobody

ENTRYPOINT ["/bin/newrelic-auth-cli"]
