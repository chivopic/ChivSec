export type FindingStatus =
  | "candidate"
  | "investigating"
  | "likely"
  | "confirmed"
  | "rejected"
  | "blocked";

export type InvariantFamily = "authorization" | "injection_sink";

export type EvidenceResult = "invariant_violated" | "invariant_held" | "inconclusive" | "error";

export type CodeRef = {
  path: string;
  startLine: number;
  endLine: number;
  snippet: string;
  why: string;
};

export type RepoFile = {
  path: string;
  content: string;
};

export type VirtualRepo = {
  id: string;
  name: string;
  summary: string;
  language: "javascript";
  files: RepoFile[];
  /** Hidden from the agent — used only by tests / lab ground-truth panel. */
  groundTruth?: GroundTruth[];
};

export type GroundTruth = {
  id: string;
  family: InvariantFamily;
  shouldConfirm: boolean;
  entry: string;
  note: string;
};

export type FunctionInfo = {
  name: string;
  params: string;
  body: string;
  path: string;
  startLine: number;
  endLine: number;
  route?: { method: string; path: string };
};

export type SinkHit = {
  kind: "exec" | "sql" | "eval";
  functionName: string;
  path: string;
  line: number;
  snippet: string;
  interpolatesInput: boolean;
};

export type Understanding = {
  language: "javascript";
  files: string[];
  entryPoints: Array<{
    id: string;
    method: string;
    path: string;
    handler: string;
    file: string;
    kind: "read" | "write" | "other";
  }>;
  functions: FunctionInfo[];
  authHelpers: string[];
  sensitiveOps: SinkHit[];
  resources: Array<{ name: string; idField: string; ownerField: string }>;
  unknowns: string[];
};

export type ThreatModel = {
  purpose: string;
  assets: Array<{ id: string; type: string; sensitivity: string }>;
  actors: Array<{ id: string; label: string }>;
  trustBoundaries: Array<{ id: string; from: string; to: string }>;
  entryPoints: Array<{
    id: string;
    boundary: string;
    authn: string;
    attackerControls: string[];
  }>;
  assumptions: string[];
  reviewPriority: string[];
};

export type Invariant = {
  id: string;
  statement: string;
  family: InvariantFamily;
  assets: string[];
  expectedFailureObservation: string;
  likelyBreakPoints: string[];
  relatedHandlers: string[];
};

export type Hypothesis = {
  id: string;
  family: InvariantFamily;
  invariantId: string;
  hypothesis: string;
  entryPoint: string;
  handler: string;
  attackerControl: string[];
  disproofPlan: string;
  file: string;
};

export type SecurityHandoff = {
  id: string;
  hypothesisId: string;
  family: InvariantFamily;
  invariantId: string;
  status: "needs_validation" | "blocked";
  hypothesis: string;
  attacker: {
    actorId: string;
    capabilities: string[];
    preconditions: string[];
  };
  locus: {
    entryPoint: string;
    source: string;
    transformations: string[];
    guardsSeen: string[];
    guardsMissing: string[];
    sink: string;
    relevantCode: CodeRef[];
  };
  discrepancy?: {
    kind: "check_vs_use" | "none";
    left: string;
    right: string;
  };
  defenses: { existing: string[]; whyInsufficient: string };
  validationPlan: {
    validatorFamily: InvariantFamily;
    slice: string;
    setup: string;
    successCriterion: string;
    failureCriterion: string;
  };
  openQuestions: string[];
};

export type DynamicEvidence = {
  validator: string;
  result: EvidenceResult;
  observation: string;
  harness: string;
  setup: {
    attacker?: string;
    resource?: string;
    expectedOwner?: string;
    status?: number;
    mutated?: boolean;
    probe?: string;
    execCalls?: string[];
    note?: string;
  };
};

export type Finding = {
  id: string;
  status: FindingStatus;
  hypothesis: string;
  invariantId: string;
  brokenInvariant: string;
  family: InvariantFamily;
  attackerControl: string[];
  attackPreconditions: string[];
  attackPath: { entry: string; steps: string[]; sink: string };
  relevantCode: CodeRef[];
  evidence: {
    static: Array<{ kind: string; detail: string }>;
    dynamic: DynamicEvidence[];
  };
  validation: {
    method: "slice_harness";
    reproduction: string;
    limitations: string[];
  };
  impact: { whatAttackerGets: string; whatIsNotClaimed: string };
  confidence: {
    exploitability: "high" | "med" | "low";
    evidenceStrength: "dynamic" | "strong_static" | "weak";
  };
  lineage: { handoffId: string; hypothesisId: string };
};

export type CostLedger = {
  filesRead: number;
  bytesIndexed: number;
  functionsParsed: number;
  hypothesesOpened: number;
  investigationsRun: number;
  validationsRun: number;
  llmCalls: number;
  llmTokens: number;
  elapsedMs: number;
};

export type StageLog = {
  id: string;
  label: string;
  detail: string;
};

export type AuditReport = {
  repoId: string;
  repoName: string;
  stages: StageLog[];
  understanding: Understanding;
  threatModel: ThreatModel;
  invariants: Invariant[];
  hypotheses: Hypothesis[];
  investigations: SecurityHandoff[];
  findings: Finding[];
  cost: CostLedger;
  summary: {
    confirmed: number;
    likely: number;
    rejected: number;
    blocked: number;
  };
};
