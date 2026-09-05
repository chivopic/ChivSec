import { cloneJson, loadSlice } from "../sandbox.ts";
import type { DynamicEvidence, SecurityHandoff, VirtualRepo } from "../types.ts";

type HandlerResult = { status?: number; body?: unknown };

function asHandler(value: unknown): ((req: unknown) => HandlerResult) | null {
  return typeof value === "function" ? (value as (req: unknown) => HandlerResult) : null;
}

function snapshotNotes(db: unknown): Array<{ id: string; ownerId: string; title: string; body: string }> {
  if (!db || typeof db !== "object") return [];
  const notes = (db as { notes?: unknown }).notes;
  if (!Array.isArray(notes)) return [];
  return notes.map((n) => ({
    id: String((n as { id: string }).id),
    ownerId: String((n as { ownerId: string }).ownerId),
    title: String((n as { title: string }).title ?? ""),
    body: String((n as { body: string }).body ?? ""),
  }));
}

export function validateAuthorization(repo: VirtualRepo, handoff: SecurityHandoff): DynamicEvidence {
  const file = repo.files.find((f) => f.path.endsWith(".js")) ?? repo.files[0];
  if (!file) {
    return {
      validator: "authorization.v1",
      result: "error",
      observation: "No JavaScript file in the slice.",
      harness: "authorization.owner-check",
      setup: {},
    };
  }

  try {
    const loaded = loadSlice(file.content);
    const handler = asHandler(loaded.exports[handoff.validationPlan.slice]);
    if (!handler) {
      return {
        validator: "authorization.v1",
        result: "inconclusive",
        observation: `Export ${handoff.validationPlan.slice} is not a function.`,
        harness: "authorization.owner-check",
        setup: {},
      };
    }

    const db = loaded.exports.db as { notes?: Array<{ id: string; ownerId: string; title: string }> } | undefined;
    const notes = snapshotNotes(db);
    const victim = notes.find((n) => n.ownerId === "user-b") ?? notes.find((n) => n.ownerId !== "user-a");
    const resourceId = victim?.id ?? "note-2";
    const before = cloneJson(snapshotNotes(db));

    const result = handler({
      user: { id: "user-a", name: "Alice" },
      params: { id: resourceId },
      query: {},
      body: { title: "pwned-by-a", body: "cross-object write" },
    });

    const after = snapshotNotes(db);
    const mutated = after.some((n, i) => {
      const prev = before[i];
      return n.ownerId !== "user-a" && prev && (n.title !== prev.title || n.body !== prev.body);
    }) || after.some((n) => n.id === resourceId && n.ownerId !== "user-a" && n.title === "pwned-by-a");

    const status = result?.status ?? 0;
    const success = status >= 200 && status < 300;
    const denied = status === 401 || status === 403 || status === 404;

    if (success && mutated) {
      return {
        validator: "authorization.v1",
        result: "invariant_violated",
        observation: `${handoff.validationPlan.slice} returned ${status} and mutated ${resourceId} owned by user-b while authenticated as user-a.`,
        harness: "authorization.owner-check",
        setup: { attacker: "user-a", resource: resourceId, expectedOwner: "user-b", status },
      };
    }

    if (denied && !mutated) {
      return {
        validator: "authorization.v1",
        result: "invariant_held",
        observation: `${handoff.validationPlan.slice} returned ${status} and left the foreign row unchanged.`,
        harness: "authorization.owner-check",
        setup: { attacker: "user-a", resource: resourceId, status },
      };
    }

    if (success && !mutated && result?.body) {
      const body = result.body as { ownerId?: string };
      if (body.ownerId && body.ownerId !== "user-a") {
        return {
          validator: "authorization.v1",
          result: "invariant_violated",
          observation: `Handler returned ${status} with a foreign resource body (owner ${body.ownerId}).`,
          harness: "authorization.owner-check",
          setup: { attacker: "user-a", resource: resourceId, status },
        };
      }
    }

    return {
      validator: "authorization.v1",
      result: denied ? "invariant_held" : "inconclusive",
      observation: `status=${status} mutated=${mutated}. Could not prove a cross-object effect.`,
      harness: "authorization.owner-check",
      setup: { attacker: "user-a", resource: resourceId, status, mutated },
    };
  } catch (err) {
    return {
      validator: "authorization.v1",
      result: "error",
      observation: err instanceof Error ? err.message : String(err),
      harness: "authorization.owner-check",
      setup: {},
    };
  }
}
