# Kubectl kept here for backwards compatibility since it was used as an init-container up until agent-control-deployment 1.6.6
# Automatically updated by Renovate
FROM alpine/kubectl:1.37.0 AS kubectl

FROM debian:trixie-slim

ARG TARGETARCH

COPY --from=kubectl /usr/local/bin/kubectl /usr/local/bin/kubectl

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y jq && \
    apt-get clean

COPY --chmod=755 target/newrelic-auth-cli-${TARGETARCH} /bin/newrelic-auth-cli

USER nobody

ENTRYPOINT ["/bin/newrelic-auth-cli"]
