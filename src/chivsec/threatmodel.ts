import type { Invariant, ThreatModel, Understanding, VirtualRepo } from "./types.ts";

export function compileThreatModel(repo: VirtualRepo, understanding: Understanding): ThreatModel {
  const writeEps = understanding.entryPoints.filter((e) => e.kind === "write");
  const hasExec = understanding.sensitiveOps.some((s) => s.kind === "exec");
  const purposeParts = [
    `${repo.name} is a small ${understanding.language} service.`,
    understanding.entryPoints.length
      ? `Public handlers: ${understanding.entryPoints.map((e) => `${e.method} ${e.path}`).join(", ")}.`
      : "No annotated HTTP entry points were found.",
  ];
  if (hasExec) purposeParts.push("It shells out for at least one operation.");
  if (writeEps.length) purposeParts.push("It mutates user-owned records over HTTP.");

  return {
    purpose: purposeParts.join(" "),
    assets: [
      { id: "asset.user_object", type: "data", sensitivity: "high" },
      ...(hasExec ? [{ id: "asset.host_command", type: "integrity", sensitivity: "high" }] : []),
    ],
    actors: [
      { id: "actor.user", label: "Authenticated user" },
      { id: "actor.peer", label: "Same-role peer (other owner)" },
    ],
    trustBoundaries: [{ id: "tb.http_public", from: "actor.user", to: "component.api" }],
    entryPoints: understanding.entryPoints.map((e) => ({
      id: e.id,
      boundary: "tb.http_public",
      authn: "session",
      attackerControls: ["params", "query", "body"],
    })),
    assumptions: [
      "Callers present a bound session user on req.user.",
      "Object identifiers in the URL are attacker-controlled.",
      "Internal helpers are not independently reachable.",
    ],
    reviewPriority: [
      ...writeEps.map((e) => `Authorization on ${e.method} ${e.path}`),
      ...understanding.sensitiveOps.map((s) => `Sink ${s.kind} in ${s.functionName}`),
    ],
  };
}

export function compileInvariants(understanding: Understanding): Invariant[] {
  const invariants: Invariant[] = [];
  const resourceHandlers = understanding.entryPoints.filter(
    (e) => e.kind === "read" || e.kind === "write",
  );
  const noteHandlers = resourceHandlers.filter((e) => /note|item|record/i.test(e.path + e.handler));

  if (noteHandlers.length || resourceHandlers.some((e) => e.kind === "write")) {
    const related = (noteHandlers.length ? noteHandlers : resourceHandlers.filter((e) => e.kind === "write")).map(
      (e) => e.handler,
    );
    invariants.push({
      id: "inv.authz.resource_owner",
      statement:
        "Only a principal with principal.id == resource.ownerId may read or mutate that resource.",
      family: "authorization",
      assets: ["asset.user_object"],
      expectedFailureObservation: "Handler returns 403/404 and the stored row is unchanged.",
      likelyBreakPoints: [
        "Authorization checks a different id than the write uses.",
        "List filters by owner but get/update loads by id only.",
        "A write handler omits the owner comparison present on sibling handlers.",
      ],
      relatedHandlers: related,
    });
  }

  const execFns = [...new Set(understanding.sensitiveOps.filter((s) => s.kind === "exec").map((s) => s.functionName))];
  if (execFns.length) {
    invariants.push({
      id: "inv.injection.command",
      statement:
        "Attacker-controlled request data must not reach a shell command string.",
      family: "injection_sink",
      assets: ["asset.host_command"],
      expectedFailureObservation: "Mocked exec() is invoked with a command containing the probe payload.",
      likelyBreakPoints: ["query/body concatenated into exec()", "unsanitized filename"],
      relatedHandlers: execFns,
    });
  }

  return invariants;
}
