import { loadConfig } from "../config.js";
import { loadPolicies } from "../policy/loader.js";
import { Store } from "../store/store.js";

try {
  process.loadEnvFile();
} catch {
  // No .env file.
}

const [command, name, policy = "default"] = process.argv.slice(2);
const config = loadConfig();
const store = new Store(config.dbPath);

switch (command) {
  case "create": {
    if (!name) usage();
    const policies = loadPolicies(config.policiesDir);
    if (!policies.has(policy)) {
      console.error(`Unknown policy "${policy}". Available: ${[...policies.keys()].join(", ")}`);
      process.exit(1);
    }
    const { tenant, apiKey } = store.createTenant(name, policy);
    console.log(`Created tenant "${tenant.name}" with policy "${policy}".`);
    console.log(`API key (shown once, store it now):\n\n  ${apiKey}\n`);
    break;
  }
  case "list":
    console.table(store.listTenants().map((t) => ({ name: t.name, policy: t.policy, key: `${t.keyPrefix}…`, monthTokens: store.getUsage(t.id) })));
    break;
  default:
    usage();
}
store.close();

function usage(): never {
  console.error("Usage:\n  npm run tenant -- create <name> [policy]\n  npm run tenant -- list");
  process.exit(1);
}
