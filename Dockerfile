FROM debian:trixie-slim

ARG TARGETARCH

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    apt-get install -y curl

RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/${TARGETARCH}/kubectl"

COPY --chmod=755 target/newrelic-auth-cli-${TARGETARCH} /bin/newrelic-auth-cli

USER nobody

ENTRYPOINT ["/bin/newrelic-auth-cli"]
