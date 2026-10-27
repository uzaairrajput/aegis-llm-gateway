import { logout } from "@/app/actions/auth";
import { getCurrentUser, pagesFor, ROLE_LABELS } from "@/lib/auth";
import { NavLinks } from "./nav";

/** Header navigation for the signed-in user. Renders nothing on the sign-in page. */
export async function UserNav() {
  const user = await getCurrentUser();
  if (!user || "error" in user) return null;

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
      <NavLinks links={pagesFor(user.role).map(({ href, label }) => ({ href, label }))} />
      <div className="flex items-center gap-3 border-l border-line pl-4">
        <div className="text-right leading-tight">
          <p className="text-sm text-ink">{user.name}</p>
          <p className="text-xs text-muted">{ROLE_LABELS[user.role]}</p>
        </div>
        <form action={logout}>
          <button type="submit" className="rounded-md border border-line px-2.5 py-1 text-xs text-ink-2 hover:bg-hover hover:text-ink">
            Sign out
          </button>
        </form>
      </div>
    </div>
  );
}
