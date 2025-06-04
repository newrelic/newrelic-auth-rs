FROM debian:trixie-slim

ARG TARGETARCH

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    apt-get install -y curl

RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/${TARGETARCH}/kubectl"
RUN chmod +x kubectl && mv kubectl /usr/local/bin/kubectl

RUN curl -Lo jq "https://github.com/jqlang/jq/releases/download/jq-1.8.0/jq-linux-${TARGETARCH}"
RUN chmod +x jq && mv jq /usr/local/bin/jq

COPY --chmod=755 target/newrelic-auth-cli-${TARGETARCH} /bin/newrelic-auth-cli

USER nobody

ENTRYPOINT ["/bin/newrelic-auth-cli"]
