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
  executeSigningPlan,
  githubCertificateIdentity,
  githubWorkflowIdentityFromEnvironment,
  imageAttestationReferences,
  sigstoreBundlePath,
  retryingVerification,
  toleratingExistingLogEntries,
  verifyPortableBlobBundle,
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

test("verifies a bounded portable blob bundle through pinned Cosign", async () => {
  const commands: string[][] = [];
  const verification = await verifyPortableBlobBundle({
    artifact: '{"certified":true}\n',
    bundle: { mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json" },
    identity,
    runner: async (command) => {
      commands.push([...command]);

      return command[1] === "version"
        ? {
            stderr: "",
            stdout: JSON.stringify({ gitVersion: COSIGN_VERSION }),
          }
        : { stderr: "", stdout: "Verified OK" };
    },
  });

  expect(commands).toHaveLength(2);
  expect(commands[1]?.[1]).toBe("verify-blob");
  expect(verification.identity).toEqual(identity);
  expect(verification.bundleSha256).toMatch(/^[a-f0-9]{64}$/u);
  await expect(
    verifyPortableBlobBundle({
      artifact: "value",
      bundle: null,
      identity,
      runner: async () => ({ stderr: "", stdout: "" }),
    }),
  ).rejects.toThrow("Sigstore bundle is invalid");
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

describe("an attestation the transparency log already holds", () => {
  const conflict = new Error(
    'cosign failed: error signing bundle: [POST /api/v1/log/entries][409] createLogEntryConflict {"code":409,"message":"an equivalent entry already exists in the transparency log with UUID 108e"}',
  );
  const failing = (error: Error) => async () => {
    throw error;
  };

  test("a sign or attest refused only as a duplicate counts as done", async () => {
    const runner = toleratingExistingLogEntries(failing(conflict));
    const results = await Promise.all(
      [
        ["cosign", "attest", "--yes", "image@sha256:abc"],
        ["cosign", "sign", "--yes", "image@sha256:abc"],
        ["cosign", "sign-blob", "--yes", "artifact.json"],
      ].map((command) => runner(command)),
    );
    for (const result of results)
      expect(result).toEqual({ stderr: conflict.message, stdout: "" });
  });

  test("verification, and every other failure, still fails", async () => {
    await expect(
      toleratingExistingLogEntries(failing(conflict))([
        "cosign",
        "verify-attestation",
        "image@sha256:abc",
      ]),
    ).rejects.toThrow("equivalent entry");
    await expect(
      toleratingExistingLogEntries(
        failing(new Error("cosign failed: tuf refresh failed")),
      )(["cosign", "attest", "image@sha256:abc"]),
    ).rejects.toThrow("tuf refresh failed");
  });

  test("a plan keeps going to the verification after a duplicate", async () => {
    const ran: string[] = [];
    const runner = toleratingExistingLogEntries(async (command) => {
      ran.push(command[1] ?? "");
      if (command[1] === "attest") throw conflict;

      return { stderr: "", stdout: "verified" };
    });
    await executeCommandPlan(
      [
        ["cosign", "attest", "image@sha256:abc"],
        ["cosign", "verify-attestation", "image@sha256:abc"],
      ],
      runner,
    );
    expect(ran).toEqual(["attest", "verify-attestation"]);
  });
});

const SHA256_HEX_LENGTH = 64;
const FIRST_DELAY = 10;
const SECOND_DELAY = 20;
const ATTEMPTS_UNTIL_VISIBLE = 3;
const DIGEST = "a".repeat(SHA256_HEX_LENGTH);
const verifySbom = [
  "cosign",
  "verify-attestation",
  "--type",
  "spdxjson",
  `ghcr.io/absolutejs/paas-actuator@sha256:${DIGEST}`,
] as const;
const notYet = new Error(
  "cosign failed: Error: none of the attestations matched the predicate type: spdxjson, found: https://slsa.dev/provenance/v1",
);

describe("verification against a lagging registry", () => {
  test("retries a verification until the attestation is visible", async () => {
    // 2026-10-28: the SBOM was verified right after it was attached and the
    // registry still served the tag from before; four images failed a release.
    let calls = 0;
    const slept: number[] = [];
    const runner = retryingVerification(
      async () => {
        calls += 1;
        if (calls < ATTEMPTS_UNTIL_VISIBLE) throw notYet;

        return { stderr: "", stdout: "verified" };
      },
      {
        delaysMs: [FIRST_DELAY, SECOND_DELAY],
        sleep: async (delay) => slept.push(delay),
      },
    );

    expect(await runner(verifySbom)).toEqual({
      stderr: "",
      stdout: "verified",
    });
    expect(calls).toBe(ATTEMPTS_UNTIL_VISIBLE);
    expect(slept).toEqual([FIRST_DELAY, SECOND_DELAY]);
  });

  test("gives up after its last delay", async () => {
    let calls = 0;
    const runner = retryingVerification(
      async () => {
        calls += 1;
        throw notYet;
      },
      { delaysMs: [FIRST_DELAY, SECOND_DELAY], sleep: async () => undefined },
    );

    await expect(runner(verifySbom)).rejects.toThrow(
      "none of the attestations",
    );
    expect(calls).toBe(ATTEMPTS_UNTIL_VISIBLE);
  });

  test("a wrong identity fails at once, never retried", async () => {
    let calls = 0;
    const runner = retryingVerification(
      async () => {
        calls += 1;
        throw new Error(
          "cosign failed: Error: none of the expected identities matched what was in the certificate",
        );
      },
      { sleep: async () => undefined },
    );

    await expect(runner(verifySbom)).rejects.toThrow("expected identities");
    expect(calls).toBe(1);
  });

  test("a signing command is never retried by it", async () => {
    let calls = 0;
    const runner = retryingVerification(
      async () => {
        calls += 1;
        throw notYet;
      },
      { sleep: async () => undefined },
    );

    await expect(
      runner(["cosign", "attest", "--yes", "--predicate", "p.json", "ref"]),
    ).rejects.toThrow();
    expect(calls).toBe(1);
  });
});

describe("an attestation that never reached the registry", () => {
  const RESIGN_ATTEMPTS = 2;
  const ATTESTS_BEFORE_GIVING_UP = RESIGN_ATTEMPTS + 1;
  const attestSbom = [
    "cosign",
    "attest",
    "--yes",
    "--predicate",
    "sbom.spdx.json",
    "--type",
    "spdxjson",
    `ghcr.io/absolutejs/paas-control-plane@sha256:${DIGEST}`,
  ] as const;

  test("runs the signing command again and verifies once more", async () => {
    // 2026-10-29: the SBOM attest left nothing in the transparency log or the
    // registry, and no amount of waiting made the verification pass.
    let attached = 0;
    const ran: string[] = [];
    const resigned: string[] = [];
    const results = await executeSigningPlan(
      [attestSbom, verifySbom],
      async (command) => {
        ran.push(command[1] ?? "");
        if (command[1] === "attest") {
          attached += 1;

          return { stderr: "", stdout: "" };
        }
        if (attached < RESIGN_ATTEMPTS) throw notYet;

        return { stderr: "", stdout: "verified" };
      },
      { onResign: (command) => resigned.push(command[1] ?? "") },
    );

    expect(ran).toEqual([
      "attest",
      "verify-attestation",
      "attest",
      "verify-attestation",
    ]);
    expect(resigned).toEqual(["attest"]);
    expect(results).toEqual([
      { stderr: "", stdout: "" },
      { stderr: "", stdout: "verified" },
    ]);
  });

  test("stops after its last attempt and keeps the verification's answer", async () => {
    let attests = 0;
    await expect(
      executeSigningPlan(
        [attestSbom, verifySbom],
        async (command) => {
          if (command[1] === "attest") {
            attests += 1;

            return { stderr: "", stdout: "" };
          }
          throw notYet;
        },
        { resignAttempts: RESIGN_ATTEMPTS },
      ),
    ).rejects.toThrow("none of the attestations");
    expect(attests).toBe(ATTESTS_BEFORE_GIVING_UP);
  });

  test("a wrong identity is never signed again", async () => {
    let attests = 0;
    await expect(
      executeSigningPlan([attestSbom, verifySbom], async (command) => {
        if (command[1] === "attest") {
          attests += 1;

          return { stderr: "", stdout: "" };
        }
        throw new Error(
          "cosign failed: Error: none of the expected identities matched what was in the certificate",
        );
      }),
    ).rejects.toThrow("expected identities");
    expect(attests).toBe(1);
  });

  test("a verification with no signing command before it is not repeated", async () => {
    let verifications = 0;
    await expect(
      executeSigningPlan([verifySbom], async () => {
        verifications += 1;
        throw notYet;
      }),
    ).rejects.toThrow("none of the attestations");
    expect(verifications).toBe(1);
  });

  test("a tolerated duplicate is reported", async () => {
    const reported: string[] = [];
    const conflict = new Error(
      "cosign failed: [409] an equivalent entry already exists in the transparency log",
    );
    await toleratingExistingLogEntries(
      async () => {
        throw conflict;
      },
      { onTolerated: (_command, message) => reported.push(message) },
    )(attestSbom);
    expect(reported).toEqual([conflict.message]);
  });
});
