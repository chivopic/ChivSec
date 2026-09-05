import type { VirtualRepo } from "./types.ts";

const TINY_NOTES = `// Tiny notes API.
// Intentional IDOR on updateNote. getNote and deleteNote check ownership.

const db = {
  users: [
    { id: "user-a", name: "Alice" },
    { id: "user-b", name: "Bob" },
  ],
  notes: [
    { id: "note-1", ownerId: "user-a", title: "Alice private", body: "secret A" },
    { id: "note-2", ownerId: "user-b", title: "Bob private", body: "secret B" },
  ],
};

function currentUser(req) {
  return req.user;
}

// @route GET /notes/:id
function getNote(req) {
  const user = currentUser(req);
  const note = db.notes.find((n) => n.id === req.params.id);
  if (!note) return { status: 404, body: { error: "not found" } };
  if (note.ownerId !== user.id) return { status: 403, body: { error: "forbidden" } };
  return { status: 200, body: note };
}

// @route PUT /notes/:id
function updateNote(req) {
  const user = currentUser(req);
  const note = db.notes.find((n) => n.id === req.params.id);
  if (!note) return { status: 404, body: { error: "not found" } };
  note.title = req.body.title != null ? req.body.title : note.title;
  note.body = req.body.body != null ? req.body.body : note.body;
  return { status: 200, body: note };
}

// @route DELETE /notes/:id
function deleteNote(req) {
  const user = currentUser(req);
  const idx = db.notes.findIndex((n) => n.id === req.params.id);
  if (idx < 0) return { status: 404, body: { error: "not found" } };
  if (db.notes[idx].ownerId !== user.id) {
    return { status: 403, body: { error: "forbidden" } };
  }
  db.notes.splice(idx, 1);
  return { status: 204, body: null };
}

function health(_req) {
  return { status: 200, body: { ok: true } };
}

module.exports = { db, currentUser, getNote, updateNote, deleteNote, health };
`;

const TINY_NOTES_FIXED = TINY_NOTES.replace(
  `  if (!note) return { status: 404, body: { error: "not found" } };
  note.title = req.body.title != null ? req.body.title : note.title;`,
  `  if (!note) return { status: 404, body: { error: "not found" } };
  if (note.ownerId !== user.id) return { status: 403, body: { error: "forbidden" } };
  note.title = req.body.title != null ? req.body.title : note.title;`,
);

const TINY_SHELL = `// Backup helper with command injection on the name query param.

const { exec } = require("child_process");

// @route GET /backup
function backup(req) {
  const name = req.query.name;
  exec("tar -czf /tmp/backup.tgz " + name);
  return { status: 200, body: { ok: true } };
}

// @route GET /health
function health(_req) {
  return { status: 200, body: { ok: true } };
}

module.exports = { backup, health };
`;

const TINY_SHELL_SAFE = `// Backup helper using argv, not shell concatenation.

const { execFile } = require("child_process");

// @route GET /backup
function backup(req) {
  const name = req.query.name;
  if (!/^[A-Za-z0-9._-]+$/.test(String(name || ""))) {
    return { status: 400, body: { error: "invalid name" } };
  }
  execFile("tar", ["-czf", "/tmp/backup.tgz", name]);
  return { status: 200, body: { ok: true } };
}

// @route GET /health
function health(_req) {
  return { status: 200, body: { ok: true } };
}

module.exports = { backup, health };
`;

export const FIXTURES: VirtualRepo[] = [
  {
    id: "tiny-notes",
    name: "tiny-notes",
    summary: "Notes API. GET/DELETE check ownership. PUT does not.",
    language: "javascript",
    files: [
      { path: "package.json", content: '{\n  "name": "tiny-notes",\n  "private": true\n}\n' },
      { path: "app.js", content: TINY_NOTES },
    ],
    groundTruth: [
      {
        id: "gt-idor-update",
        family: "authorization",
        shouldConfirm: true,
        entry: "PUT /notes/:id",
        note: "updateNote writes a note without comparing ownerId to the caller.",
      },
      {
        id: "gt-get-held",
        family: "authorization",
        shouldConfirm: false,
        entry: "GET /notes/:id",
        note: "getNote rejects cross-user reads. Must not be confirmed.",
      },
    ],
  },
  {
    id: "tiny-notes-fixed",
    name: "tiny-notes-fixed",
    summary: "Same notes API after the ownership check is added to PUT.",
    language: "javascript",
    files: [
      { path: "package.json", content: '{\n  "name": "tiny-notes-fixed",\n  "private": true\n}\n' },
      { path: "app.js", content: TINY_NOTES_FIXED },
    ],
    groundTruth: [
      {
        id: "gt-update-held",
        family: "authorization",
        shouldConfirm: false,
        entry: "PUT /notes/:id",
        note: "updateNote now checks ownerId. Harness must report held.",
      },
    ],
  },
  {
    id: "tiny-shell",
    name: "tiny-shell",
    summary: "Backup endpoint concatenates query.name into a shell command.",
    language: "javascript",
    files: [
      { path: "package.json", content: '{\n  "name": "tiny-shell",\n  "private": true\n}\n' },
      { path: "app.js", content: TINY_SHELL },
    ],
    groundTruth: [
      {
        id: "gt-cmdi",
        family: "injection_sink",
        shouldConfirm: true,
        entry: "GET /backup",
        note: "attacker-controlled name reaches exec().",
      },
    ],
  },
  {
    id: "tiny-shell-safe",
    name: "tiny-shell-safe",
    summary: "Backup endpoint validates the name and uses execFile argv.",
    language: "javascript",
    files: [
      { path: "package.json", content: '{\n  "name": "tiny-shell-safe",\n  "private": true\n}\n' },
      { path: "app.js", content: TINY_SHELL_SAFE },
    ],
    groundTruth: [
      {
        id: "gt-cmdi-held",
        family: "injection_sink",
        shouldConfirm: false,
        entry: "GET /backup",
        note: "payload must not reach a shell string.",
      },
    ],
  },
];

export function getFixture(id: string): VirtualRepo | undefined {
  return FIXTURES.find((f) => f.id === id);
}

export function repoFromSource(source: string): VirtualRepo {
  return {
    id: "custom",
    name: "pasted-slice",
    summary: "User-pasted JavaScript slice.",
    language: "javascript",
    files: [{ path: "app.js", content: source }],
  };
}
