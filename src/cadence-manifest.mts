// SPDX-License-Identifier: AGPL-3.0-or-later
import { openSync, fstatSync, readSync, closeSync, constants } from "node:fs";
import { z } from "zod";

const id = z.string().min(1).max(200);
const at = z.iso.datetime();
const uri = z
  .string()
  .max(2048)
  .refine((value) => {
    if (/^sha256:[a-f0-9]{64}$/.test(value)) return true;
    try {
      const u = new URL(value);
      return u.protocol === "https:" && !u.username && !u.password && !u.search;
    } catch {
      return false;
    }
  }, "Use a stable HTTPS reference without credentials/query parameters, or a SHA-256 reference");
export const cadenceTarget = z
  .object({
    host: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/),
    project_id: z.string().min(1).max(2048),
    thread_id: z.string().min(1).max(2048),
    run_id: z.string().min(1).max(2048),
    role: z.enum(["work", "watcher"]).default("work"),
  })
  .strict();
const ownership = z.object({ by: id, at, source: z.literal("owner_record") }).strict();
export const cadenceGoal = z
  .object({
    id,
    owner: id,
    title: z.string().min(1).max(500),
    revision: z.number().int().positive(),
    created_at: at,
    execution_owner: id,
    targets: z.array(cadenceTarget).min(1).max(8),
    artifacts: z
      .array(z.object({ id, target: z.number().int().min(0).max(7), uri, revision: id }).strict())
      .max(40),
    finish_criteria: z
      .array(
        z
          .object({
            id,
            description: z.string().min(1).max(1000),
            artifact_id: id,
            assertion: z.enum(["checks_passed", "merged", "activated", "content_verified"]),
          })
          .strict(),
      )
      .min(1)
      .max(40),
    next_action: z
      .object({
        description: z.string().min(1).max(1000),
        owner: id.nullable(),
        waiting_reason: z.string().min(1).max(1000).nullable(),
        decision_needed: z.boolean().default(false),
      })
      .strict(),
    handoffs: z
      .array(
        z
          .object({
            id,
            target: z.number().int().min(0).max(7),
            request_id: z.string().uuid(),
            from: id,
            to: id,
            proposed_at: at,
            acceptance: ownership.optional(),
            acknowledgement: ownership.optional(),
          })
          .strict(),
      )
      .max(40)
      .default([]),
    verifications: z
      .array(
        z
          .object({
            criterion_id: id,
            goal_revision: z.number().int().positive(),
            artifact_id: id,
            artifact_revision: id,
            target_run_id: id,
            assertion: z.enum(["checks_passed", "merged", "activated", "content_verified"]),
            verifier: id,
            independent_of: id,
            verified_at: at,
            evidence_uri: uri,
            source: z.literal("operator_independent_attestation"),
          })
          .strict(),
      )
      .max(80)
      .default([]),
  })
  .strict()
  .superRefine((g, context) => {
    const unique = (values) => new Set(values).size === values.length;
    if (
      !unique(
        g.targets.map((t) => JSON.stringify([t.host, t.project_id, t.thread_id, t.run_id])),
      ) ||
      !unique(g.artifacts.map((a) => a.id)) ||
      !unique(g.finish_criteria.map((c) => c.id)) ||
      !unique(g.handoffs.map((h) => h.id))
    )
      context.addIssue({ code: "custom", message: "Duplicate cadence binding" });
    if (!g.targets.some((t) => t.role === "work"))
      context.addIssue({ code: "custom", message: "A cadence goal needs a work target" });
    if (
      g.finish_criteria.some((c) => {
        const a = g.artifacts.find((a) => a.id === c.artifact_id);
        return a && g.targets[a.target]?.role !== "work";
      })
    )
      context.addIssue({ code: "custom", message: "Watcher activity cannot verify a work goal" });
    if (
      g.artifacts.some((a) => a.target >= g.targets.length) ||
      g.handoffs.some((h) => h.target >= g.targets.length) ||
      g.finish_criteria.some((c) => !g.artifacts.some((a) => a.id === c.artifact_id))
    )
      context.addIssue({ code: "custom", message: "Unbound cadence reference" });
  });
export const cadenceManifest = z
  .object({ version: z.literal(1), goals: z.array(cadenceGoal).max(500) })
  .strict()
  .superRefine((value, context) => {
    const keys = value.goals.map((g) => JSON.stringify([g.owner, g.id]));
    if (new Set(keys).size !== keys.length)
      context.addIssue({ code: "custom", message: "Duplicate goal identity" });
  });
export type CadenceGoal = z.infer<typeof cadenceGoal>;
export type CadenceTarget = z.infer<typeof cadenceTarget>;

// Bounded descriptor read; no path selected by a remote tool and no write API.
// Cache only an unchanged open-file fingerprint, never policy/authorization.
export function goalManifestFile(path: string): () => unknown {
  let fingerprint: string | undefined, cached: unknown;
  return () => {
    let fd: number | undefined;
    try {
      fd = openSync(
        path,
        constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
      );
      const before = fstatSync(fd, { bigint: true });
      if (!before.isFile() || before.size > 1048576n) throw Error();
      if (process.platform !== "win32" && (before.mode & 0o022n) !== 0n) throw Error();
      const key = [before.dev, before.ino, before.size, before.mtimeNs, before.ctimeNs].join(":");
      if (key === fingerprint) return cached;
      const buffer = Buffer.alloc(Number(before.size) + 1);
      let bytes = 0,
        read: number;
      do {
        read = readSync(fd, buffer, bytes, buffer.length - bytes, null);
        bytes += read;
      } while (read && bytes < buffer.length);
      const after = fstatSync(fd, { bigint: true });
      if (
        bytes !== Number(before.size) ||
        after.size !== before.size ||
        after.mtimeNs !== before.mtimeNs ||
        after.ctimeNs !== before.ctimeNs
      )
        throw Error();
      cached = cadenceManifest.parse(JSON.parse(buffer.subarray(0, bytes).toString("utf8")));
      fingerprint = key;
      return cached;
    } catch {
      throw Object.assign(Error("cadence_manifest_unavailable"), {
        reason: "cadence_manifest_unavailable",
      });
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
  };
}
