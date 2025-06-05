FROM debian:trixie-slim

ARG TARGETARCH

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean

RUN apt-get install -y curl kubectl jq

COPY --chmod=755 target/newrelic-auth-cli-${TARGETARCH} /bin/newrelic-auth-cli

USER nobody

ENTRYPOINT ["/bin/newrelic-auth-cli"]
