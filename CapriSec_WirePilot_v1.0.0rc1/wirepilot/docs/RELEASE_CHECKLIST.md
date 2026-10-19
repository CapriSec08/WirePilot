# Release acceptance

## Prepared in this package

- Source, wheel-build metadata, MIT licence, changelog and contribution/security guidance.
- Claude configuration generator, stdio smoke client and synthetic fixture/test matrix.
- CI/dependency update definitions. GitHub execution is pending repository creation/upload.
- Explicit supported features, limits and remaining platform checks.

## Required before a stable public release

1. Complete the Claude/OS matrix in TESTING_WITH_CLAUDE.md. Reproduce every advertised
   capability on the platform you claim to support; resolve or explicitly exclude skips.
2. Run a clean installation and wheel smoke check. Run `pytest`, fatal lint, wheel build
   and dependency audit. Record exact versions and rerun after dependency changes.
3. Evaluate labelled benign and attack examples beyond bundled synthetic fixtures.
   Record false alarms and misses; do not publish unsupported accuracy percentages.
4. Inspect the release ZIP/repository for private captures, credentials, local state,
   reports, generated Claude paths or unrelated files. Only synthetic examples belong here.
5. Review the MIT licence choice/copyright, repository description and limitations.
   Create the repository, enable private vulnerability reporting and run the included CI.
6. Publish a tagged RC/alpha first if stable acceptance remains incomplete. Promote to
   1.0.0 only after acceptance; do not merely rename the version while tests remain unresolved.

The downloaded RC is not a claim of universal attack detection or L3-equivalent coverage.
No publication, git push, deployment or PyPI upload has been performed automatically.
Vendor device APIs, NetFlow, learned baselines and executed VeloPilot/LEON integration
remain future capabilities and should not appear as completed in release marketing.
