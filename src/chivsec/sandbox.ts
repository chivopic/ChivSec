import vm from "node:vm";

export type SandboxRun = {
  exports: Record<string, unknown>;
  execCalls: string[];
  execFileCalls: Array<{ cmd: string; args: unknown[] }>;
};

export function loadSlice(source: string): SandboxRun {
  const execCalls: string[] = [];
  const execFileCalls: Array<{ cmd: string; args: unknown[] }> = [];

  const child_process = {
    exec(command: string, _opts?: unknown, cb?: (err: Error | null, stdout: string, stderr: string) => void) {
      execCalls.push(String(command));
      if (typeof _opts === "function") {
        (_opts as (err: Error | null, stdout: string, stderr: string) => void)(null, "", "");
        return { pid: 0 };
      }
      if (cb) cb(null, "", "");
      return { pid: 0 };
    },
    execSync(command: string) {
      execCalls.push(String(command));
      return Buffer.from("");
    },
    spawn() {
      execCalls.push("<spawn>");
      return { pid: 0, on() {}, stdout: { on() {} }, stderr: { on() {} } };
    },
    execFile(cmd: string, args?: unknown[], _opts?: unknown, cb?: (...args: unknown[]) => void) {
      execFileCalls.push({ cmd: String(cmd), args: Array.isArray(args) ? args : [] });
      if (typeof args === "function") {
        (args as (err: Error | null) => void)(null);
        return { pid: 0 };
      }
      if (typeof _opts === "function") {
        (_opts as (err: Error | null) => void)(null);
        return { pid: 0 };
      }
      if (cb) cb(null);
      return { pid: 0 };
    },
  };

  const moduleObj: { exports: Record<string, unknown> } = { exports: {} };
  const context = vm.createContext({
    module: moduleObj,
    exports: moduleObj.exports,
    require: (name: string) => {
      if (name === "child_process") return child_process;
      throw new Error(`sandbox blocked require(${name})`);
    },
    console: { log() {}, warn() {}, error() {} },
    Buffer,
    setTimeout,
    clearTimeout,
  });

  const wrapped = `"use strict";\n${source}\n`;
  vm.runInContext(wrapped, context, { timeout: 800, displayErrors: true });
  const exported = (context as { module: { exports: Record<string, unknown> } }).module.exports;
  return { exports: exported, execCalls, execFileCalls };
}

export function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
