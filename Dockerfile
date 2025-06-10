FROM debian:trixie-slim

ARG TARGETARCH

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean

RUN apt-get install -y busybox curl kubectl jq
RUN ln -s /bin/busybox /bin/ash

COPY --chmod=755 target/newrelic-auth-cli-${TARGETARCH} /bin/newrelic-auth-cli

ENTRYPOINT ["/bin/newrelic-auth-cli"]
