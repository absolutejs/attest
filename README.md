# @absolutejs/attest

Keyless software-supply-chain attestation for private CI pipelines.

`@absolutejs/attest` binds an immutable container digest or release file to an
exact GitHub Actions repository, workflow, ref, and commit. It creates SLSA v1
provenance predicates, builds fail-closed Cosign command plans, stores image
provenance and SPDX SBOM attestations beside the image in its OCI registry, and
creates portable Sigstore bundles for ordinary release files.

The package does not implement cryptography, operate a certificate authority,
or replace Sigstore. The official Cosign client performs signing and
verification against Fulcio, Rekor, and the Sigstore trust root. This package
owns the reusable policy that tells Cosign exactly which workflow identity and
artifact digest are acceptable.

## Why this is not part of `@absolutejs/deploy`

Attestation happens before deployment and remains useful without a deployer.
Build systems produce evidence, registries retain it, admission controls verify
it, and offline release reviewers inspect it. `@absolutejs/deploy` may require
valid evidence before activation, but it should not own the trust model.

## GitHub Actions identity

```ts
import {
  createImagePublicationCommands,
  githubWorkflowIdentityFromEnvironment,
} from "@absolutejs/attest";

const identity = githubWorkflowIdentityFromEnvironment(process.env);
const commands = createImagePublicationCommands({
  identity,
  imageReference:
    "ghcr.io/acme/api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  provenancePath: "evidence/provenance.json",
  sbomPath: "evidence/sbom.spdx.json",
});
```

Every verification command requires:

- the exact Fulcio OIDC issuer;
- the exact GitHub repository;
- the exact workflow file;
- the exact branch or tag ref;
- the exact source commit;
- a digest-pinned OCI image reference.

Tags such as `latest`, abbreviated commits, unqualified workflow names, and
non-GitHub invocation URLs are rejected.

## CLI

The package exports `absolute-attest` for CI jobs:

```sh
absolute-attest provenance evidence/provenance.json
absolute-attest publish-image \
  "$IMAGE_NAME@$IMAGE_DIGEST" \
  evidence/provenance.json \
  evidence/sbom.spdx.json \
  evidence/attestations.json
absolute-attest sign-blobs \
  release/release.json \
  release/images.env \
  release/sha256sums.txt
absolute-attest verify-blobs \
  release/release.json \
  release/images.env \
  release/sha256sums.txt
```

The CLI reads GitHub's standard `GITHUB_REPOSITORY`, `GITHUB_WORKFLOW_REF`,
`GITHUB_REF`, `GITHUB_SHA`, `GITHUB_SERVER_URL`, and `GITHUB_RUN_ID`
variables. None are credentials. Cosign obtains the job's short-lived OIDC
identity directly from GitHub Actions.

## Security properties

- No long-lived signing key.
- No custom cryptography.
- Immediate verification after every signing or attestation operation.
- Exact certificate identity and GitHub workflow claims.
- SHA-256 digest-pinned images only.
- SLSA v1 provenance bound to the source commit and workflow invocation.
- SPDX JSON SBOM attestations stored with the OCI image.
- Portable Sigstore bundles for non-container release files.
- Sequential execution that stops at the first violated boundary.

MIT licensed.
