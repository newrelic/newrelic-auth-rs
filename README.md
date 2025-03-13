| ⚠️ | `nr-auth` is in preview and licensed under the New Relic Pre-Release Software Notice. |
|----|:----------------------------------------------------------------------------------------------------|

# `nr-auth`

[![🧪 On PR testing](https://github.com/newrelic/newrelic-oauth-client-rs/actions/workflows/on-push-pr.yaml/badge.svg)](https://github.com/newrelic/newrelic-oauth-client-rs/actions/workflows/on-push-pr.yaml) [![docs](https://github.com/newrelic/newrelic-auth-rs/actions/workflows/docs.yaml/badge.svg)](https://newrelic.github.io/newrelic-auth-rs/)

`nr-auth` aims to provide all the functionality needed to authenticate with System Identity Service and retrieve
authorization tokens to make authenticated and authorized requests to Fleet Control.

## Installation

The library is not available on [`crates.io`](https://crates.io/) for now, but you can still use it from this repository by adding the following line to your project's `Cargo.toml`:

```toml
[dependencies]
nr-auth = { git = "ssh://git@github.com/newrelic/newrelic-auth-rs.git", tag = "0.0.4" }
```

## Getting Started

See the [top level module](./src/lib.rs) documentation for details.

## Support

If you find any problems while using the library or have a doubt, please feel free to open an [Issue](https://github.com/newrelic/newrelic-oauth-client-rs/issues), where the New Relic maintainers of this project will be able to help.

## Contribute

We encourage your contributions to improve [project name]! Keep in mind that when you submit your pull request, you'll need to sign the CLA via the click-through using CLA-Assistant. You only have to sign the CLA one time per project.

If you have any questions, or to execute our corporate CLA (which is required if your contribution is on behalf of a company), drop us an email at <opensource@newrelic.com>.

### A note about vulnerabilities

As noted in our [security policy](../../security/policy), New Relic is committed to the privacy and security of our customers and their data. We believe that providing coordinated disclosure by security researchers and engaging with the security community are important means to achieve our security goals.

If you believe you have found a security vulnerability in this project or any of New Relic's products or websites, we welcome and greatly appreciate you reporting it to New Relic through [our bug bounty program](https://docs.newrelic.com/docs/security/security-privacy/information-security/report-security-vulnerabilities/).

If you would like to contribute to this project, review [these guidelines](./CONTRIBUTING.md).

To all contributors, we thank you! Without your contribution, this project would not be what it is today.

## License

`newrelic-auth-rs` is licensed under the New Relic Prerelease Software License.

This project also uses source code from third-party libraries. You can find full details on which libraries are used and the terms under which they are licensed in the third-party notices document.

## Tracking of old Pull Requests

Head to the [private archive](https://github.com/newrelic/newrelic-oauth-client-rs).
