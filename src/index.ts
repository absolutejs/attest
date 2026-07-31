import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com";
const GITHUB_HOST = "https://github.com";
const IMAGE_NAME_PATTERN =
  /^[a-z0-9.-]+(?::[0-9]+)?(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$/u;
const OCI_PREFIX = "oci://";
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const SOURCE_REVISION_PATTERN = /^[a-f0-9]{40}$/u;
const WORKFLOW_PATH_PATTERN = /^\.github\/workflows\/[^/@]+\.ya?ml$/u;
const GITHUB_REF_PATTERN = /^refs\/(?:heads|tags)\/[^@\s]+$/u;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const SLSA_PROVENANCE_TYPE = "slsaprovenance1";
const SPDX_TYPE = "spdxjson";

export const COSIGN_VERSION = "v3.1.2";

export type CommandResult = {
  stderr: string;
  stdout: string;
};

export type CommandRunner = (
  command: readonly string[],
) => Promise<CommandResult>;

export type GithubWorkflowIdentity = {
  issuer: string;
  ref: string;
  repository: string;
  sha: string;
  workflowPath: string;
};

export type GithubWorkflowEnvironment = {
  GITHUB_REF?: string;
  GITHUB_REPOSITORY?: string;
  GITHUB_RUN_ID?: string;
  GITHUB_SERVER_URL?: string;
  GITHUB_SHA?: string;
  GITHUB_WORKFLOW_REF?: string;
};

export type SlsaProvenancePredicate = {
  buildDefinition: {
    buildType: string;
    externalParameters: {
      ref: string;
      repository: string;
      workflowPath: string;
    };
    internalParameters: Record<string, never>;
    resolvedDependencies: Array<{
      digest: { gitCommit: string };
      uri: string;
    }>;
  };
  runDetails: {
    builder: { id: string };
    metadata: { invocationId: string };
  };
};

export type ImageAttestationReferences = {
  provenance: string;
  sbom: string;
  signature: string;
};

export class AttestationPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AttestationPolicyError";
  }
}

const required = (value: string | undefined, name: string) => {
  const candidate = value?.trim();
  if (!candidate) throw new AttestationPolicyError(`${name} is required`);

  return candidate;
};

const assertMatch = (value: string, pattern: RegExp, description: string) => {
  if (!pattern.test(value))
    throw new AttestationPolicyError(`${description} is invalid`);

  return value;
};

const assertImageReference = (reference: string) => {
  const separator = reference.lastIndexOf("@");
  if (separator <= 0)
    throw new AttestationPolicyError(
      "Image reference must be pinned by digest",
    );
  const name = reference.slice(0, separator);
  const digest = reference.slice(separator + 1);
  if (!IMAGE_NAME_PATTERN.test(name) || !SHA256_PATTERN.test(digest))
    throw new AttestationPolicyError(
      "Image reference must use a canonical registry name and SHA-256 digest",
    );

  return reference;
};

const assertArtifactPath = (artifactPath: string) => {
  const candidate = required(artifactPath, "artifact path");
  if (
    candidate.startsWith("-") ||
    candidate.includes("\0") ||
    candidate.endsWith("/")
  )
    throw new AttestationPolicyError("Artifact path is unsafe");

  return candidate;
};

const verificationArguments = (identity: GithubWorkflowIdentity) => [
  "--certificate-identity",
  githubCertificateIdentity(identity),
  "--certificate-oidc-issuer",
  identity.issuer,
  "--certificate-github-workflow-repository",
  identity.repository,
  "--certificate-github-workflow-ref",
  identity.ref,
  "--certificate-github-workflow-sha",
  identity.sha,
];

export const assertCosignVersion = async (runner: CommandRunner) => {
  const result = await runner(["cosign", "version", "--json"]);
  const version = /"gitVersion"\s*:\s*"([^"]+)"/u.exec(result.stdout)?.[1];
  if (version !== COSIGN_VERSION)
    throw new AttestationPolicyError(
      `Cosign ${COSIGN_VERSION} is required; received ${version ?? "unknown"}`,
    );

  return version;
};
export const createBlobSigningCommands = (input: {
  artifactPath: string;
  identity: GithubWorkflowIdentity;
}) => {
  const identity = defineGithubWorkflowIdentity(input.identity);
  const artifactPath = assertArtifactPath(input.artifactPath);
  const bundlePath = sigstoreBundlePath(artifactPath);

  return [
    ["cosign", "sign-blob", "--yes", "--bundle", bundlePath, artifactPath],
    [
      "cosign",
      "verify-blob",
      "--bundle",
      bundlePath,
      ...verificationArguments(identity),
      artifactPath,
    ],
  ];
};
export const createBlobVerificationCommand = (input: {
  artifactPath: string;
  identity: GithubWorkflowIdentity;
}) => [
  "cosign",
  "verify-blob",
  "--bundle",
  sigstoreBundlePath(assertArtifactPath(input.artifactPath)),
  ...verificationArguments(defineGithubWorkflowIdentity(input.identity)),
  assertArtifactPath(input.artifactPath),
];
export const createImagePublicationCommands = (input: {
  identity: GithubWorkflowIdentity;
  imageReference: string;
  provenancePath: string;
  sbomPath: string;
}) => {
  const identity = defineGithubWorkflowIdentity(input.identity);
  const reference = assertImageReference(input.imageReference);
  const provenancePath = assertArtifactPath(input.provenancePath);
  const sbomPath = assertArtifactPath(input.sbomPath);
  const [verifyProvenance, verifySbom, verifySignature] =
    createImageVerificationCommands({
      identity,
      imageReference: reference,
    });

  return [
    [
      "cosign",
      "attest",
      "--yes",
      "--predicate",
      provenancePath,
      "--type",
      SLSA_PROVENANCE_TYPE,
      reference,
    ],
    verifyProvenance,
    [
      "cosign",
      "attest",
      "--yes",
      "--predicate",
      sbomPath,
      "--type",
      SPDX_TYPE,
      reference,
    ],
    verifySbom,
    ["cosign", "sign", "--yes", reference],
    verifySignature,
  ];
};
export const createImageVerificationCommands = (input: {
  identity: GithubWorkflowIdentity;
  imageReference: string;
}) => {
  const identity = defineGithubWorkflowIdentity(input.identity);
  const reference = assertImageReference(input.imageReference);
  const verify = verificationArguments(identity);

  return [
    [
      "cosign",
      "verify-attestation",
      ...verify,
      "--type",
      SLSA_PROVENANCE_TYPE,
      reference,
    ],
    ["cosign", "verify-attestation", ...verify, "--type", SPDX_TYPE, reference],
    ["cosign", "verify", ...verify, reference],
  ] as const;
};
export const createSlsaProvenancePredicate = (input: {
  identity: GithubWorkflowIdentity;
  invocationUrl: string;
}) => {
  const identity = defineGithubWorkflowIdentity(input.identity);
  const invocationUrl = new URL(input.invocationUrl);
  const invocationPrefix = `/${identity.repository}/actions/runs/`;
  const invocationRunId = invocationUrl.pathname.slice(invocationPrefix.length);
  if (
    invocationUrl.protocol !== "https:" ||
    invocationUrl.hostname !== "github.com" ||
    !invocationUrl.pathname.startsWith(invocationPrefix) ||
    !/^[1-9][0-9]*$/u.test(invocationRunId) ||
    invocationUrl.search ||
    invocationUrl.hash
  )
    throw new AttestationPolicyError(
      "Invocation URL must be an HTTPS GitHub URL",
    );

  return {
    buildDefinition: {
      buildType:
        "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
      externalParameters: {
        ref: identity.ref,
        repository: `${GITHUB_HOST}/${identity.repository}`,
        workflowPath: identity.workflowPath,
      },
      internalParameters: {},
      resolvedDependencies: [
        {
          digest: { gitCommit: identity.sha },
          uri: `git+${GITHUB_HOST}/${identity.repository}@${identity.ref}`,
        },
      ],
    },
    runDetails: {
      builder: { id: "https://github.com/actions/runner/github-hosted" },
      metadata: { invocationId: invocationUrl.href },
    },
  } satisfies SlsaProvenancePredicate;
};
export const defineGithubWorkflowIdentity = (
  input: GithubWorkflowIdentity,
): GithubWorkflowIdentity => ({
  issuer: required(input.issuer, "issuer"),
  ref: assertMatch(
    required(input.ref, "ref"),
    GITHUB_REF_PATTERN,
    "GitHub ref",
  ),
  repository: assertMatch(
    required(input.repository, "repository"),
    REPOSITORY_PATTERN,
    "GitHub repository",
  ),
  sha: assertMatch(
    required(input.sha, "sha"),
    SOURCE_REVISION_PATTERN,
    "GitHub source revision",
  ),
  workflowPath: assertMatch(
    required(input.workflowPath, "workflowPath"),
    WORKFLOW_PATH_PATTERN,
    "GitHub workflow path",
  ),
});
export const executeCommandPlan = async (
  commands: ReadonlyArray<ReadonlyArray<string>>,
  runner: CommandRunner,
) =>
  commands.reduce(
    async (resultsPromise, command) => [
      ...(await resultsPromise),
      await runner(command),
    ],
    Promise.resolve<CommandResult[]>([]),
  );
export const githubCertificateIdentity = (input: GithubWorkflowIdentity) => {
  const identity = defineGithubWorkflowIdentity(input);

  return `${GITHUB_HOST}/${identity.repository}/${identity.workflowPath}@${identity.ref}`;
};
export const githubWorkflowIdentityFromEnvironment = (
  environment: GithubWorkflowEnvironment,
) => {
  const repository = required(
    environment.GITHUB_REPOSITORY,
    "GITHUB_REPOSITORY",
  );
  const workflowReference = required(
    environment.GITHUB_WORKFLOW_REF,
    "GITHUB_WORKFLOW_REF",
  );
  const prefix = `${repository}/`;
  const separator = workflowReference.lastIndexOf("@");
  if (!workflowReference.startsWith(prefix) || separator <= prefix.length)
    throw new AttestationPolicyError("GITHUB_WORKFLOW_REF is invalid");

  return defineGithubWorkflowIdentity({
    issuer: GITHUB_ACTIONS_ISSUER,
    ref: required(environment.GITHUB_REF, "GITHUB_REF"),
    repository,
    sha: required(environment.GITHUB_SHA, "GITHUB_SHA"),
    workflowPath: workflowReference.slice(prefix.length, separator),
  });
};
export const imageAttestationReferences = (
  imageReference: string,
): ImageAttestationReferences => {
  const reference = assertImageReference(imageReference);

  return {
    provenance: `${OCI_PREFIX}${reference}#${SLSA_PROVENANCE_TYPE}`,
    sbom: `${OCI_PREFIX}${reference}#${SPDX_TYPE}`,
    signature: `${OCI_PREFIX}${reference}#signature`,
  };
};
export const sigstoreBundlePath = (artifactPath: string) =>
  `${assertArtifactPath(artifactPath)}.sigstore.json`;
export const writeSlsaProvenancePredicate = async (
  outputPath: string,
  input: Parameters<typeof createSlsaProvenancePredicate>[0],
) => {
  const predicate = createSlsaProvenancePredicate(input);
  await mkdir(path.dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(predicate, null, 2)}\n`);

  return predicate;
};
