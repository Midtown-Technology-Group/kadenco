// SPDX-License-Identifier: AGPL-3.0-or-later
import { performance } from "node:perf_hooks";
export const syncOperations = new Set([
  "policy",
  "backend.read",
  "store.get",
  "store.all",
  "store.put",
  "store.insert",
  "store.audit",
  "store.diagnostic",
  "store.transaction",
]);
export class SynchronousTimings {
  private maximum = 0;
  private operation: string | null = null;
  private cpu = process.cpuUsage();
  measure<T>(operation: string, fn: () => T): T {
    const start = performance.now();
    try {
      return fn();
    } finally {
      const elapsed = performance.now() - start;
      if (syncOperations.has(operation) && elapsed > this.maximum) {
        this.maximum = elapsed;
        this.operation = operation;
      }
    }
  }
  wrap(target, prefix: string, names: string[]) {
    for (const name of names) {
      const original = target[name],
        operation = prefix + "." + name;
      if (typeof original !== "function" || !syncOperations.has(operation)) continue;
      const descriptor = Object.getOwnPropertyDescriptor(target, name);
      if (
        (descriptor && (!Object.hasOwn(descriptor, "value") || descriptor.writable === false)) ||
        (!descriptor && !Object.isExtensible(target))
      )
        continue;
      const measure = this.measure.bind(this);
      target[name] = function (...args) {
        return measure(operation, () => original.apply(this, args));
      };
    }
  }
  take() {
    const cpu = process.cpuUsage(this.cpu);
    this.cpu = process.cpuUsage();
    const result = {
      sync_operation: this.operation,
      sync_operation_max_ms: this.maximum,
      process_cpu_user_ms: cpu.user / 1000,
      process_cpu_system_ms: cpu.system / 1000,
    };
    this.maximum = 0;
    this.operation = null;
    return result;
  }
}
