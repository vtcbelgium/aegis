const fs = require("fs");
const vm = require("vm");

const src = fs.readFileSync(process.argv[2], "utf8");

function loadBackground() {
  let listener = null;
  const storage = {
    blockedCount: 5,
    threatHistory: [{ type: "prompt_injection" }],
    protectionActive: true,
    allowlist: []
  };
  let rulesetUpdates = [];
  const sandbox = {
    Map,
    Array,
    Object,
    String,
    Boolean,
    console,
    chrome: {
      runtime: {
        id: "aegis-ext-id-123",
        onInstalled: { addListener: () => {} },
        onMessage: { addListener: (fn) => { listener = fn; } }
      },
      tabs: {
        onRemoved: { addListener: () => {} },
        onUpdated: { addListener: () => {} }
      },
      action: {
        setBadgeText: () => {},
        setBadgeBackgroundColor: () => {}
      },
      declarativeNetRequest: {
        updateEnabledRulesets: (opts) => {
          rulesetUpdates.push(opts);
          return Promise.resolve();
        }
      },
      storage: {
        local: {
          get: (_keys, cb) => cb({ ...storage }),
          set: (patch, cb) => {
            Object.assign(storage, patch);
            if (cb) cb();
          }
        }
      }
    }
  };
  vm.runInNewContext(src, sandbox);
  return {
    send(message, sender) {
      let resp = null;
      listener(message, sender, (r) => { resp = r; });
      return resp;
    },
    storage,
    rulesetUpdates
  };
}

let pass = 0, fail = 0;
function check(name, cond) { cond ? pass++ : (fail++, console.log("FAIL:", name)); }

// Content script (sender.tab present) MUST NOT disable protection, allowlist, or wipe history
let bg = loadBackground();
let r = bg.send({ type: "AEGIS_SET_PROTECTION", active: false }, { id: "aegis-ext-id-123", tab: { id: 7 } });
check("content script cannot disable protection", r && r.ok === false && bg.storage.protectionActive === true);

r = bg.send({ type: "AEGIS_TOGGLE_ALLOWLIST", hostname: "evil.example" }, { id: "aegis-ext-id-123", tab: { id: 7 } });
check("content script cannot mutate allowlist", r && r.ok === false && bg.storage.allowlist.length === 0);

r = bg.send({ type: "AEGIS_CLEAR_HISTORY" }, { id: "aegis-ext-id-123", tab: { id: 7 } });
check("content script cannot clear history", r && r.ok === false && bg.storage.blockedCount === 5);

// Foreign extension id MUST be rejected even without sender.tab
r = bg.send({ type: "AEGIS_SET_PROTECTION", active: false }, { id: "other-ext-999" });
check("foreign extension cannot disable protection", r && r.ok === false && bg.storage.protectionActive === true);

// Trusted popup (same extension id, no sender.tab) MUST succeed
r = bg.send({ type: "AEGIS_SET_PROTECTION", active: false }, { id: "aegis-ext-id-123" });
check("popup can toggle protection", r && r.ok === true && bg.storage.protectionActive === false);

r = bg.send({ type: "AEGIS_TOGGLE_ALLOWLIST", hostname: "example.com" }, { id: "aegis-ext-id-123" });
check("popup can toggle allowlist", r && r.ok === true && bg.storage.allowlist.includes("example.com"));

r = bg.send({ type: "AEGIS_CLEAR_HISTORY" }, { id: "aegis-ext-id-123" });
check("popup can clear history", r && r.ok === true && bg.storage.blockedCount === 0);

console.log(`${pass}/${pass + fail} passed`);
process.exit(fail ? 1 : 0);
