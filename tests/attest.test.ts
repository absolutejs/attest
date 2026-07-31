import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, test } from "bun:test";
import {
  AttestationPolicyError,
  assertCosignVersion,
  COSIGN_VERSION,
  createBlobSigningCommands,
  createBlobVerificationCommand,
  createImagePublicationCommands,
  createImageVerificationCommands,
  createSlsaProvenancePredicate,
  defineGithubWorkflowIdentity,
  executeCommandPlan,
  githubCertificateIdentity,
  githubWorkflowIdentityFromEnvironment,
  imageAttestationReferences,
  sigstoreBundlePath,
  writeSlsaProvenancePredicate,
  type GithubWorkflowIdentity,
} from "../src";

const SOURCE_REVISION_LENGTH = 40;
const DIGEST_LENGTH = 64;
const LAST_ELEMENT = -1;
const SOURCE_REVISION = "a".repeat(SOURCE_REVISION_LENGTH);
const IMAGE_DIGEST = `sha256:${"b".repeat(DIGEST_LENGTH)}`;
const identity: GithubWorkflowIdentity = {
  issuer: "https://token.actions.githubusercontent.com",
  ref: "refs/heads/main",
  repository: "absolutejs/PAAS",
  sha: SOURCE_REVISION,
  workflowPath: ".github/workflows/image-supply-chain.yml",
};

describe("GitHub workflow identity", () => {
  test("derives an exact certificate identity and rejects mutable inputs", () => {
    expect(githubCertificateIdentity(identity)).toBe(
      "https://github.com/absolutejs/PAAS/.github/workflows/image-supply-chain.yml@refs/heads/main",
    );
    expect(
      githubWorkflowIdentityFromEnvironment({
        GITHUB_REF: identity.ref,
        GITHUB_REPOSITORY: identity.repository,
        GITHUB_SHA: identity.sha,
        GITHUB_WORKFLOW_REF: `${identity.repository}/${identity.workflowPath}@${identity.ref}`,
      }),
    ).toEqual(identity);
    expect(() =>
      defineGithubWorkflowIdentity({
        ...identity,
        ref: "main",
      }),
    ).toThrow(AttestationPolicyError);
    expect(() =>
      defineGithubWorkflowIdentity({
        ...identity,
        sha: "latest",
      }),
    ).toThrow(AttestationPolicyError);
    expect(() =>
      defineGithubWorkflowIdentity({
        ...identity,
        workflowPath: "../release.yml",
      }),
    ).toThrow(AttestationPolicyError);
  });
});

test("builds SLSA provenance bound to the exact source and invocation", async () => {
  const predicate = createSlsaProvenancePredicate({
    identity,
    invocationUrl: "https://github.com/absolutejs/PAAS/actions/runs/123456",
  });
  expect(predicate.buildDefinition.resolvedDependencies).toEqual([
    {
      digest: { gitCommit: SOURCE_REVISION },
      uri: "git+https://github.com/absolutejs/PAAS@refs/heads/main",
    },
  ]);
  expect(predicate.runDetails.metadata.invocationId).toBe(
    "https://github.com/absolutejs/PAAS/actions/runs/123456",
  );
  expect(() =>
    createSlsaProvenancePredicate({
      identity,
      invocationUrl: "https://github.com/attacker/repo/actions/runs/123456",
    }),
  ).toThrow("Invocation URL");

  const directory = await mkdtemp(
    path.join(tmpdir(), "absolute-attest-provenance-"),
  );
  try {
    const outputPath = path.join(directory, "nested", "provenance.json");
    await writeSlsaProvenancePredicate(outputPath, {
      identity,
      invocationUrl: "https://github.com/absolutejs/PAAS/actions/runs/123456",
    });
    expect(JSON.parse(await readFile(outputPath, "utf8"))).toEqual(predicate);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("builds a fail-closed image publication and verification plan", () => {
  const reference = `ghcr.io/absolutejs/paas-edge@${IMAGE_DIGEST}`;
  const commands = createImagePublicationCommands({
    identity,
    imageReference: reference,
    provenancePath: "evidence/provenance.json",
    sbomPath: "evidence/sbom.spdx.json",
  });
  expect(commands.map(([binary, action]) => [binary, action])).toEqual([
    ["cosign", "attest"],
    ["cosign", "verify-attestation"],
    ["cosign", "attest"],
    ["cosign", "verify-attestation"],
    ["cosign", "sign"],
    ["cosign", "verify"],
  ]);
  for (const command of commands.filter(
    ([, action]) => action?.startsWith("verify") ?? false,
  )) {
    expect(command).toContain("--certificate-identity");
    expect(command).toContain("--certificate-oidc-issuer");
    expect(command).toContain("--certificate-github-workflow-repository");
    expect(command).toContain("--certificate-github-workflow-ref");
    expect(command).toContain("--certificate-github-workflow-sha");
    expect(command.at(LAST_ELEMENT)).toBe(reference);
  }
  expect(imageAttestationReferences(reference)).toEqual({
    provenance: `oci://${reference}#slsaprovenance1`,
    sbom: `oci://${reference}#spdxjson`,
    signature: `oci://${reference}#signature`,
  });
  expect(() =>
    createImagePublicationCommands({
      identity,
      imageReference: "ghcr.io/absolutejs/paas-edge:latest",
      provenancePath: "provenance.json",
      sbomPath: "sbom.json",
    }),
  ).toThrow("pinned by digest");
  expect(() =>
    createImagePublicationCommands({
      identity,
      imageReference: `ghcr.io/absolutejs/paas-edge:latest@${IMAGE_DIGEST}`,
      provenancePath: "provenance.json",
      sbomPath: "sbom.json",
    }),
  ).toThrow("canonical registry name");
});

test("builds a verification-only image admission plan", () => {
  const reference = `ghcr.io/absolutejs/paas-edge@${IMAGE_DIGEST}`;
  const commands = createImageVerificationCommands({
    identity,
    imageReference: reference,
  });
  expect(commands.map(([binary, action]) => [binary, action])).toEqual([
    ["cosign", "verify-attestation"],
    ["cosign", "verify-attestation"],
    ["cosign", "verify"],
  ]);
  expect(commands[0]).toContain("slsaprovenance1");
  expect(commands[1]).toContain("spdxjson");
  for (const command of commands) {
    expect(command).toContain("--certificate-github-workflow-sha");
    expect(command.at(LAST_ELEMENT)).toBe(reference);
  }
});

test("builds portable blob bundles with immediate identity verification", () => {
  const artifactPath = "release/release.json";
  const bundlePath = `${artifactPath}.sigstore.json`;
  expect(sigstoreBundlePath(artifactPath)).toBe(bundlePath);
  const commands = createBlobSigningCommands({ artifactPath, identity });
  expect(commands[0]).toEqual([
    "cosign",
    "sign-blob",
    "--yes",
    "--new-bundle-format=true",
    "--bundle",
    bundlePath,
    artifactPath,
  ]);
  expect(commands[1]).toEqual(
    createBlobVerificationCommand({ artifactPath, identity }),
  );
  expect(() =>
    createBlobSigningCommands({
      artifactPath: "--key",
      identity,
    }),
  ).toThrow("unsafe");
});

test("pins Cosign before trusting command behavior", async () => {
  await expect(
    assertCosignVersion(async () => ({
      stderr: "",
      stdout: JSON.stringify({ gitVersion: COSIGN_VERSION }),
    })),
  ).resolves.toBe(COSIGN_VERSION);
  await expect(
    assertCosignVersion(async () => ({
      stderr: "",
      stdout: JSON.stringify({ gitVersion: "v3.0.5" }),
    })),
  ).rejects.toThrow(`Cosign ${COSIGN_VERSION} is required`);
});

test("executes plans sequentially and stops at the first failed boundary", async () => {
  const seen: string[] = [];
  await expect(
    executeCommandPlan(
      [
        ["cosign", "sign"],
        ["cosign", "verify"],
        ["cosign", "attest"],
      ],
      async (command) => {
        const action = command[1] ?? "";
        seen.push(action);
        if (action === "verify") throw new Error("synthetic failure");

        return { stderr: "", stdout: "" };
      },
    ),
  ).rejects.toThrow("synthetic failure");
  expect(seen).toEqual(["sign", "verify"]);
});
