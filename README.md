<a href="https://opensource.newrelic.com/oss-category/#community-project"><picture><source media="(prefers-color-scheme: dark)" srcset="https://github.com/newrelic/opensource-website/raw/main/src/images/categories/dark/Community_Project.png"><source media="(prefers-color-scheme: light)" srcset="https://github.com/newrelic/opensource-website/raw/main/src/images/categories/Community_Project.png"><img alt="New Relic Open Source community project banner." src="https://github.com/newrelic/opensource-website/raw/main/src/images/categories/Community_Project.png"></picture></a>

| ⚠️ | `nr-auth` is in preview and licensed under the New Relic Pre-Release Software Notice. |
|----|:----------------------------------------------------------------------------------------------------|

# `nr-auth`

`nr-auth` aims to provide all the functionality needed to authenticate with System Identity Service and retrieve
authorization tokens to make authenticated and authorized requests to Fleet Control.

## Installation

The library is not available on [`crates.io`](https://crates.io/) for now, but you can still use it from this repository by adding the following line to your project's `Cargo.toml`:

```toml
[dependencies]
nr-auth = { git = "https://github.com/newrelic/newrelic-auth-rs.git", tag = "0.0.4" }
```

## Getting Started

See the [documentation](https://newrelic.github.io/newrelic-auth-rs/) documentation for details.

## Support

* [New Relic Community](https://forum.newrelic.com/): The best place to engage in troubleshooting questions.
* [Issues](https://github.com/newrelic/newrelic-auth-rs/issues): If you find any problems while using the library, feel free to open an issue where the New Relic maintainers of this project will be able to help.

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

## Upstream archive

[Link](https://github.com/newrelic/newrelic-oauth-client-rs) (private, for NR employees).
