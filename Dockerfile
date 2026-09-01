FROM debian:trixie-slim

ARG TARGETARCH

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y curl jq && \
    apt-get clean

COPY --chmod=755 target/newrelic-auth-cli-${TARGETARCH} /bin/newrelic-auth-cli

USER nobody

ENTRYPOINT ["/bin/newrelic-auth-cli"]
