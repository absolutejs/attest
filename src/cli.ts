#!/usr/bin/env bun

import { writeFile } from "node:fs/promises";
import {
  AttestationPolicyError,
  assertCosignVersion,
  createBlobSigningCommands,
  createBlobVerificationCommand,
  createImagePublicationCommands,
  createImageVerificationCommands,
  executeCommandPlan,
  githubWorkflowIdentityFromEnvironment,
  imageAttestationReferences,
  sigstoreBundlePath,
  writeSlsaProvenancePredicate,
  type CommandRunner,
  type GithubWorkflowEnvironment,
} from "./index";

const COMMAND_INDEX = 2;
const FIRST_ARGUMENT_INDEX = 3;
const SECOND_ARGUMENT_INDEX = 4;
const THIRD_ARGUMENT_INDEX = 5;
const FOURTH_ARGUMENT_INDEX = 6;
const environment: GithubWorkflowEnvironment = {
  GITHUB_REF: process.env.GITHUB_REF,
  GITHUB_REPOSITORY: process.env.GITHUB_REPOSITORY,
  GITHUB_RUN_ID: process.env.GITHUB_RUN_ID,
  GITHUB_SERVER_URL: process.env.GITHUB_SERVER_URL,
  GITHUB_SHA: process.env.GITHUB_SHA,
  GITHUB_WORKFLOW_REF: process.env.GITHUB_WORKFLOW_REF,
};

const runner: CommandRunner = async (command) => {
  const child = Bun.spawn([...command], {
    stderr: "pipe",
    stdout: "pipe",
  });
  const [exitCode, stderr, stdout] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
    new Response(child.stdout).text(),
  ]);
  if (exitCode !== 0)
    throw new Error(
      `${command[0]} failed: ${stderr.trim() || `exit ${exitCode}`}`,
    );

  return { stderr, stdout };
};

const requiredArgument = (index: number, description: string) => {
  const candidate = process.argv[index]?.trim();
  if (!candidate)
    throw new AttestationPolicyError(`${description} is required`);

  return candidate;
};

const invocationUrl = () => {
  const server = environment.GITHUB_SERVER_URL?.trim();
  const repository = environment.GITHUB_REPOSITORY?.trim();
  const runId = environment.GITHUB_RUN_ID?.trim();
  if (!server || !repository || !runId)
    throw new AttestationPolicyError(
      "GITHUB_SERVER_URL, GITHUB_REPOSITORY, and GITHUB_RUN_ID are required",
    );

  return `${server}/${repository}/actions/runs/${runId}`;
};

const command = process.argv[COMMAND_INDEX];

if (command === "provenance") {
  const identity = githubWorkflowIdentityFromEnvironment(environment);
  const outputPath = requiredArgument(
    FIRST_ARGUMENT_INDEX,
    "provenance output path",
  );
  await writeSlsaProvenancePredicate(outputPath, {
    identity,
    invocationUrl: invocationUrl(),
  });
} else if (command === "publish-image") {
  const identity = githubWorkflowIdentityFromEnvironment(environment);
  const imageReference = requiredArgument(
    FIRST_ARGUMENT_INDEX,
    "image reference",
  );
  const provenancePath = requiredArgument(
    SECOND_ARGUMENT_INDEX,
    "provenance path",
  );
  const sbomPath = requiredArgument(THIRD_ARGUMENT_INDEX, "SBOM path");
  const evidencePath = requiredArgument(
    FOURTH_ARGUMENT_INDEX,
    "evidence output path",
  );
  await assertCosignVersion(runner);
  await executeCommandPlan(
    createImagePublicationCommands({
      identity,
      imageReference,
      provenancePath,
      sbomPath,
    }),
    runner,
  );
  await writeFile(
    evidencePath,
    `${JSON.stringify(imageAttestationReferences(imageReference), null, 2)}\n`,
  );
} else if (command === "sign-blobs") {
  const identity = githubWorkflowIdentityFromEnvironment(environment);
  const artifactPaths = process.argv.slice(FIRST_ARGUMENT_INDEX);
  if (artifactPaths.length === 0)
    throw new AttestationPolicyError(
      "sign-blobs requires at least one artifact path",
    );
  await assertCosignVersion(runner);
  await executeCommandPlan(
    artifactPaths.flatMap((artifactPath) =>
      createBlobSigningCommands({ artifactPath, identity }),
    ),
    runner,
  );
} else if (command === "verify-blobs") {
  const identity = githubWorkflowIdentityFromEnvironment(environment);
  const artifactPaths = process.argv.slice(FIRST_ARGUMENT_INDEX);
  if (artifactPaths.length === 0)
    throw new AttestationPolicyError(
      "verify-blobs requires at least one artifact path",
    );
  await assertCosignVersion(runner);
  await executeCommandPlan(
    artifactPaths.map((artifactPath) =>
      createBlobVerificationCommand({ artifactPath, identity }),
    ),
    runner,
  );
} else if (command === "verify-image") {
  const identity = githubWorkflowIdentityFromEnvironment(environment);
  const imageReference = requiredArgument(
    FIRST_ARGUMENT_INDEX,
    "image reference",
  );
  await assertCosignVersion(runner);
  await executeCommandPlan(
    createImageVerificationCommands({ identity, imageReference }),
    runner,
  );
} else if (command === "bundle-path") {
  console.log(
    sigstoreBundlePath(requiredArgument(FIRST_ARGUMENT_INDEX, "artifact path")),
  );
} else {
  throw new AttestationPolicyError(
    "Command must be provenance, publish-image, sign-blobs, verify-blobs, verify-image, or bundle-path",
  );
}
