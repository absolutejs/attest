import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<Record<string, never>>()({
  contract: 2,
  identity: {
    accent: "#8b5cf6",
    category: "security",
    description:
      "Keyless Sigstore policy, SLSA provenance, OCI image attestations, signed blob bundles, and exact GitHub Actions identity verification.",
    docsUrl: "https://github.com/absolutejs/attest",
    name: "@absolutejs/attest",
    tagline: "Prove exactly what built every release.",
  },
  integration: {
    description:
      "Hosts provide their repository, workflow, ref, source revision, image references, and release paths while the package owns Sigstore policy and command construction.",
    mode: "code-first",
  },
  settings: Type.Object({}),
  wiring: [],
});
