# Open-core model

Agent Effect Gate has a usable, self-hosted MIT core. Every source file and feature shipped in this repository is covered by [LICENSE](LICENSE), subject to any explicitly preserved third-party notices. The existing Boundary Layer contributors attribution remains intact.

The public core includes policy enforcement, exact-request approvals, task budgets, the Linux sandbox, authenticated Unix clients, audit records, reviewer accounts and console, CLI, MCP, framework adapters, checkpointed runs, backup and recovery tools. None of these features requires a commercial license, subscription, license server or hosted service from the maintainer. Optional third-party providers have their own terms and charges.

## Separate commercial extensions

The planned commercial edition would add organization-wide services around the core, such as enterprise identity provisioning, fleet administration, managed audit retention and hosted operations. These are product directions, not claims of implemented or purchasable capabilities. There is no commercial edition in this release.

Commercial implementations, if developed, will live in separate repositories or packages with explicit commercial terms. They must not be required to build, test or run this public core. This repository contains no proprietary code or placeholder proprietary license. Contributions here are accepted under MIT.

Existing MIT grants continue to apply to code already released under MIT. Commercial work does not retroactively restrict that code. New enterprise features must be clearly identified and documented before being offered. See [COMMERCIAL.md](COMMERCIAL.md) for the proposed boundary.
