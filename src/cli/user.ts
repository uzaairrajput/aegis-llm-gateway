import { generatePassword, hashPassword } from "../auth/password.js";
import { loadConfig } from "../config.js";
import { ROLES, Store, type Role } from "../store/store.js";

try {
  process.loadEnvFile();
} catch {
  // No .env file.
}

const [command, email, role, ...nameParts] = process.argv.slice(2);
const store = new Store(loadConfig().dbPath);

switch (command) {
  case "create": {
    if (!email || !ROLES.includes(role as Role)) usage();
    if (store.findUserForLogin(email)) {
      console.error(`A user with email ${email} already exists.`);
      process.exit(1);
    }
    // Generated, never typed: it can't end up in shell history and is always strong.
    const password = generatePassword();
    const name = nameParts.join(" ") || email.split("@")[0]!;
    const user = store.createUser({ email, name, role: role as Role, passwordHash: await hashPassword(password) });
    console.log(`Created ${user.role} "${user.name}" <${user.email}>.`);
    console.log(`Password (shown once, store it in a password manager):\n\n  ${password}\n`);
    break;
  }
  case "list":
    console.table(
      store.listUsers().map((u) => ({
        email: u.email,
        name: u.name,
        role: u.role,
        lastLogin: u.lastLoginAt ? new Date(u.lastLoginAt).toISOString() : "never",
      })),
    );
    break;
  case "delete":
    if (!email) usage();
    console.log(store.deleteUser(email) ? `Deleted ${email}. Their sessions stop working on the next page load.` : `No user ${email}.`);
    break;
  default:
    usage();
}
store.close();

function usage(): never {
  console.error(
    `Usage:\n  npm run user -- create <email> <${ROLES.join("|")}> [display name]\n  npm run user -- list\n  npm run user -- delete <email>`,
  );
  process.exit(1);
}
