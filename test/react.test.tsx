// @vitest-environment jsdom
// The sign-in gate keeps the browser's theme and language the person's own, kept in Identity when it manages them
// (ADR 0033). fetch stands in for the product and for Identity.
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { useLocalePreference, useThemePreference } from "@openasy/ui";
import { useEffect, useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Preferences } from "../src/client.ts";
import { AccountSettings, AuthGate, useAccountMenu, useAuth } from "../src/react.tsx";

const IDENTITY = "https://id.example.com";

let kept: Preferences;
let sent: Array<{ url: string; body: unknown }>;

function me(managed: boolean) {
  return {
    user: {
      id: "u1",
      email: "uma@example.com",
      name: "Uma",
      role: "viewer",
      status: "active",
      createdAt: "",
      lastSignInAt: null,
      mfa: { totp: false, passkeys: 0 },
      providers: ["sso"],
    },
    session: { id: "s1", method: "oidc:sso", mfa: true, factor: null },
    passwordManagedBy: null,
    mfaSetupRequired: false,
    hasPassword: false,
    passkeys: [],
    recoveryCodesLeft: 0,
    managedBy: managed ? { name: "OpenAsy Identity", url: IDENTITY } : null,
    preferences: kept,
  };
}

function serve(managed: boolean) {
  const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const url = String(input);
      if (url === "/api/v1/auth/methods")
        return json({ passwords: true, passkeys: false, users: false, providers: [], autoRedirect: null, setupRequired: false, brand: null });
      if (url === "/api/v1/auth/me") return json(me(managed));
      if (url === `${managed ? IDENTITY : ""}/api/v1/auth/me/preferences`) {
        if (init.method === "PATCH") {
          const body = JSON.parse(String(init.body)) as Partial<Preferences>;
          sent.push({ url, body });
          kept = { ...kept, ...body };
        }
        return json(kept);
      }
      return new Response("{}", { status: 404 });
    }),
  );
}

function Product() {
  const { me } = useAuth();
  const [theme, setTheme] = useThemePreference();
  const [locale] = useLocalePreference();
  return (
    <div>
      <p data-testid="shown">{`${me.user.name} ${theme} ${locale}`}</p>
      <button onClick={() => setTheme("light")}>light</button>
    </div>
  );
}

beforeEach(() => {
  localStorage.clear();
  sent = [];
  kept = { name: "Uma", theme: null, locale: null };
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("preferences kept in Identity", () => {
  it("shows what was chosen in Identity, its name too, and sends nothing back", async () => {
    kept = { name: "Uma Park", theme: "dark", locale: "tr" };
    serve(true);
    render(<AuthGate>{<Product />}</AuthGate>);
    await waitFor(() => expect(screen.getByTestId("shown").textContent).toBe("Uma Park dark tr"));
    expect(localStorage.getItem("oa-theme")).toBe("dark");
    expect(sent).toEqual([]);
  });

  it("sends a choice made in the product to Identity, and follows a change made there when the person comes back", async () => {
    kept = { name: "Uma", theme: "dark", locale: "en" };
    serve(true);
    render(<AuthGate>{<Product />}</AuthGate>);
    await waitFor(() => expect(screen.getByTestId("shown").textContent).toBe("Uma dark en"));
    act(() => screen.getByText("light").click());
    await waitFor(() => expect(sent).toEqual([{ url: `${IDENTITY}/api/v1/auth/me/preferences`, body: { theme: "light" } }]));
    // Changed in Identity meanwhile; seen when the window gets the focus again.
    kept = { ...kept, theme: "system", name: "Uma P." };
    act(() => void window.dispatchEvent(new Event("focus")));
    await waitFor(() => expect(screen.getByTestId("shown").textContent).toBe("Uma P. system en"));
    expect(localStorage.getItem("oa-theme")).toBeNull();
    expect(sent).toHaveLength(1);
  });

  it("makes what this browser chose before the person's own, once", async () => {
    localStorage.setItem("oa-theme", "light");
    serve(true);
    render(<AuthGate>{<Product />}</AuthGate>);
    await waitFor(() => expect(sent).toEqual([{ url: `${IDENTITY}/api/v1/auth/me/preferences`, body: { theme: "light" } }]));
    expect(screen.getByTestId("shown").textContent).toContain("light");
  });

  it("sends the account page to Identity, with the page before it to come back to", async () => {
    serve(true);
    const assign = vi.fn();
    const real = window.location;
    vi.stubGlobal("location", {
      get href() {
        return real.href;
      },
      get hash() {
        return real.hash;
      },
      get origin() {
        return real.origin;
      },
      get pathname() {
        return real.pathname;
      },
      get search() {
        return real.search;
      },
      assign,
    });
    history.pushState(null, "", "/findings?tab=open");
    function Pages() {
      const [account, setAccount] = useState(false);
      useEffect(() => {
        const moved = () => setAccount(real.pathname === "/account");
        window.addEventListener("popstate", moved);
        return () => window.removeEventListener("popstate", moved);
      }, []);
      return account ? <AccountSettings /> : <p>findings</p>;
    }
    render(<AuthGate>{<Pages />}</AuthGate>);
    await screen.findByText("findings");
    act(() => {
      history.pushState(null, "", "/account");
      window.dispatchEvent(new PopStateEvent("popstate"));
    });
    const back = encodeURIComponent(`${real.origin}/findings?tab=open`);
    await waitFor(() => expect(assign).toHaveBeenCalledWith(`${IDENTITY}/account?from=${back}`));
  });

  it("leaves Identity's pages out of the menu and leads the account there", async () => {
    serve(true);
    const shown: string[][] = [];
    function Menu() {
      const account = useAccountMenu();
      shown.push(account.settings([{ id: "setup" }, { id: "members" }, { id: "signin" }, { id: "tokens" }, { id: "account" }]).map((i) => i.id));
      return <a href={account.user.accountHref}>account</a>;
    }
    render(<AuthGate>{<Menu />}</AuthGate>);
    const link = await screen.findByText("account");
    expect(shown.at(-1)).toEqual(["setup", "tokens"]);
    expect(link.getAttribute("href")).toBe(`${IDENTITY}/account?from=${encodeURIComponent(location.href)}`);
  });

  it("keeps them in the product itself without Identity", async () => {
    serve(false);
    render(<AuthGate>{<Product />}</AuthGate>);
    await waitFor(() => expect(screen.getByTestId("shown").textContent).toContain("Uma"));
    act(() => screen.getByText("light").click());
    await waitFor(() => expect(sent).toEqual([{ url: "/api/v1/auth/me/preferences", body: { theme: "light" } }]));
  });
});
