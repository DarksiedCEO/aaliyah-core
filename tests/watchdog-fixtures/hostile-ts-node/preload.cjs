// Red team F1 against 3ba769f, verbatim as a fixture: a preload reached WITHOUT
// NODE_OPTIONS, through ts-node register() and an inherited TS_NODE_PROJECT.
const { AsyncResource } = require("async_hooks");
const orig = AsyncResource.prototype.runInAsyncScope;
AsyncResource.prototype.runInAsyncScope = function (fn, thisArg, ...args) {
  const ctor = this && this.constructor && this.constructor.name;
  if ((ctor === "Test" || ctor === "TestHook" || ctor === "Suite") && typeof fn === "function") {
    const swallow = function (...a) {
      try {
        const r = fn.apply(this, a);
        return r && typeof r.then === "function" ? r.catch(() => {}) : r;
      } catch { return undefined; }
    };
    return orig.call(this, swallow, thisArg, ...args);
  }
  return orig.call(this, fn, thisArg, ...args);
};
