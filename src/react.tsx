// Screens for @openasy/auth, built from @openasy/ui: the sign-in gate around a product's UI, and the Account, Members
// and API tokens settings. They follow the Identity/Sign-in stories in the ui Storybook.
import { Badge, Button, Callout, Panel, SelectField, TextField, useBrand } from "@openasy/ui";
import { ArrowLeft, Copy, Download, Fingerprint, KeyRound, LogIn, Plus, ShieldCheck, Smartphone, Trash2 } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ClipboardEvent, type FormEvent, type KeyboardEvent, type ReactNode } from "react";
import { encode } from "uqr";
import { auth, AuthApiError, passkeysSupported, takeAuthParams, type ApiToken, type Me, type Member, type Methods, type Role, type Session } from "./client.ts";

export { auth, AuthApiError, type Me, type Member, type Role } from "./client.ts";

const ROLE_NAMES: Record<Role, string> = { owner: "Owner", admin: "Admin", editor: "Editor", viewer: "Viewer" };
const RANK: Role[] = ["viewer", "editor", "admin", "owner"];
const message = (err: unknown) => (err instanceof Error ? err.message : String(err));
/** The person closed the browser's passkey prompt: not an error worth showing. */
const cancelled = (err: unknown) => err instanceof Error && (err.name === "NotAllowedError" || err.name === "AbortError");

// ---- Context ------------------------------------------------------------------------------------------------------

interface AuthContextValue {
  me: Me;
  /** True when the signed-in person has at least this role. */
  can: (role: Role) => boolean;
  refresh: () => Promise<void>;
  signOut: () => Promise<void>;
  /** Call when the product's API answers 401: shows the sign-in screen again. */
  expired: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);
/** The product's name for headings ("Sign in to ..."); the brand's name when the product gives none. */
const ProductContext = createContext<string | undefined>(undefined);
function useProductName() {
  const product = useContext(ProductContext);
  const { brand } = useBrand();
  return product ?? brand.name;
}

export function useAuth(): AuthContextValue {
  const v = useContext(AuthContext);
  if (!v) throw new Error("useAuth must be used inside <AuthGate>");
  return v;
}

// ---- Layout -------------------------------------------------------------------------------------------------------

function Mark({ size = 40 }: { size?: number }) {
  const { brand, theme } = useBrand();
  const logo = theme === "dark" ? (brand.logoDarkUrl ?? brand.logoUrl) : brand.logoUrl;
  if (logo) return <img src={logo} alt="" width={size} height={size} className="rounded-lg object-contain" />;
  return (
    <span aria-hidden className="grid place-items-center rounded-lg bg-accent text-lg font-semibold text-accent-contrast" style={{ width: size, height: size }}>
      {brand.name.trim().charAt(0).toUpperCase()}
    </span>
  );
}

function AuthLayout({ children, wide = false }: { children: ReactNode; wide?: boolean }) {
  const { brand } = useBrand();
  const product = useContext(ProductContext);
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4 bg-canvas px-4 py-10 text-fg">
      <div className="flex w-full flex-col gap-4 rounded-xl border border-line bg-surface p-6 shadow-raised" style={{ maxWidth: wide ? 460 : 380 }}>
        <div className="flex flex-col items-center gap-2 text-center">
          <Mark />
          <span className="text-sm font-semibold text-fg">{brand.name}</span>
          {(brand.organization ?? product) && <span className="-mt-1.5 text-xs text-fg-muted">{brand.organization ?? product}</span>}
        </div>
        {children}
      </div>
      {!brand.hidePoweredBy && <footer className="text-xs text-fg-muted">Powered by OpenAsy</footer>}
    </main>
  );
}

function Heading({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-1 text-center">
      <h1 className="text-lg font-semibold text-fg">{title}</h1>
      {children && <p className="text-sm text-fg-muted">{children}</p>}
    </div>
  );
}

function Divider({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-center gap-2 text-xs text-fg-muted">
      <span aria-hidden className="h-px grow bg-line" />
      {children}
      <span aria-hidden className="h-px grow bg-line" />
    </div>
  );
}

function Problem({ error, title = "Something went wrong" }: { error?: string; title?: string }) {
  return error ? (
    <Callout tone="danger" title={title}>
      {error}
    </Callout>
  ) : null;
}

/** Six boxes for a TOTP code; typing, pasting, backspace and arrow keys move between them. */
function CodeInput({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const refs = useRef<Array<HTMLInputElement | null>>([]);
  const focus = (i: number) => refs.current[Math.max(0, Math.min(5, i))]?.focus();
  const setAt = (i: number, ch: string) => {
    const next = value.slice();
    next[i] = ch;
    onChange(next);
  };
  const onKey = (i: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace" && !value[i] && i > 0) {
      e.preventDefault();
      setAt(i - 1, "");
      focus(i - 1);
    } else if (e.key === "ArrowLeft") {
      e.preventDefault();
      focus(i - 1);
    } else if (e.key === "ArrowRight") {
      e.preventDefault();
      focus(i + 1);
    }
  };
  const onPaste = (e: ClipboardEvent<HTMLInputElement>) => {
    const digits = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6);
    if (!digits) return;
    e.preventDefault();
    onChange(Array.from({ length: 6 }, (_, k) => digits[k] ?? ""));
    focus(digits.length);
  };
  return (
    <fieldset className="flex flex-col gap-1.5">
      <legend className="mb-1.5 text-xs font-medium text-fg">Authentication code</legend>
      <div className="flex justify-between gap-1.5">
        {Array.from({ length: 6 }, (_, i) => (
          <input
            key={i}
            ref={(el) => {
              refs.current[i] = el;
            }}
            aria-label={`Digit ${i + 1}`}
            inputMode="numeric"
            autoComplete={i === 0 ? "one-time-code" : "off"}
            maxLength={1}
            value={value[i] ?? ""}
            onChange={(e) => {
              const ch = e.target.value.replace(/\D/g, "").slice(-1);
              setAt(i, ch);
              if (ch && i < 5) focus(i + 1);
            }}
            onKeyDown={(e) => onKey(i, e)}
            onPaste={onPaste}
            onFocus={(e) => e.currentTarget.select()}
            className="h-10 w-10 rounded-md border border-line-strong bg-surface text-center font-mono text-lg text-fg"
          />
        ))}
      </div>
    </fieldset>
  );
}

const EMPTY_CODE = () => Array<string>(6).fill("");

/** Dark modules on white whatever the theme, so phone cameras can read it. */
function QrCode({ text, size = 176 }: { text: string; size?: number }) {
  const { data } = encode(text, { border: 2 });
  const n = data.length;
  let d = "";
  data.forEach((row, y) => row.forEach((on, x) => on && (d += `M${x} ${y}h1v1h-1z`)));
  return (
    <svg role="img" aria-label="QR code for the authenticator app" viewBox={`0 0 ${n} ${n}`} width={size} height={size} shapeRendering="crispEdges" className="rounded-md">
      <rect width={n} height={n} fill="#fff" />
      <path d={d} fill="#000" />
    </svg>
  );
}

function copy(text: string) {
  void navigator.clipboard?.writeText(text);
}

function download(name: string, text: string) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

/** Shown once after the first second factor, or when they are replaced. */
function RecoveryCodes({ codes, productName, onDone }: { codes: string[]; productName: string; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  const text = `${productName} recovery codes\nEach code works once.\n\n${codes.join("\n")}\n`;
  return (
    <div className="flex flex-col gap-3">
      <Callout tone="warning" title="Save your recovery codes">
        If you lose your phone or passkey, each of these codes signs you in once. They are not shown again.
      </Callout>
      <ul aria-label="Recovery codes" className="grid grid-cols-2 gap-1.5 rounded-md border border-line bg-canvas p-3 font-mono text-sm" style={{ listStyle: "none", margin: 0 }}>
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <div className="flex gap-2">
        <Button size="sm" icon={<Copy />} onClick={() => copy(codes.join("\n"))}>
          Copy
        </Button>
        <Button size="sm" icon={<Download />} onClick={() => download(`${productName.toLowerCase().replace(/\W+/g, "-")}-recovery-codes.txt`, text)}>
          Download
        </Button>
      </div>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />I saved them somewhere safe
      </label>
      <Button variant="primary" disabled={!saved} onClick={onDone}>
        Continue
      </Button>
    </div>
  );
}

// ---- Sign-in screens ----------------------------------------------------------------------------------------------

function PasswordFields({ password, setPassword, confirm, setConfirm }: { password: string; setPassword: (v: string) => void; confirm: string; setConfirm: (v: string) => void }) {
  return (
    <>
      <TextField label="Password" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} hint="At least 12 characters. A few unrelated words work well." />
      <TextField
        label="Repeat password"
        type="password"
        autoComplete="new-password"
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
        error={confirm && confirm !== password ? "The passwords differ." : undefined}
      />
    </>
  );
}

const passwordOk = (p: string, c: string) => p.length >= 12 && p === c;

function SignIn({ methods, initialError, onSignedIn, onMfa }: { methods: Methods; initialError?: string; onSignedIn: () => void; onMfa: (methods: string[]) => void }) {
  const name = useProductName();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(initialError);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!email || !password) return setError("Enter your email and password.");
    setBusy(true);
    try {
      const r = await auth.signIn(email, password);
      if (r.status === "mfa-required") onMfa(r.methods);
      else onSignedIn();
    } catch (err) {
      setError(message(err));
      setBusy(false);
    }
  };
  const passkey = async () => {
    try {
      await auth.signInWithPasskey();
      onSignedIn();
    } catch (err) {
      if (!cancelled(err)) setError(message(err));
    }
  };
  return (
    <AuthLayout>
      <h1 className="text-center text-lg font-semibold text-fg">Sign in to {name}</h1>
      <Problem error={error} title="Could not sign in" />
      {methods.passwords && (
        <form className="flex flex-col gap-2.5" onSubmit={submit} noValidate>
          <TextField label="Email" type="email" autoComplete="username webauthn" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} />
          <TextField
            label="Password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            hint="Forgot it? Ask an admin for a new password link."
          />
          <Button type="submit" variant="primary" icon={<LogIn />} className="w-full" loading={busy}>
            Sign in
          </Button>
        </form>
      )}
      {(methods.providers.length > 0 || passkeysSupported()) && methods.passwords && <Divider>or</Divider>}
      <div className="flex flex-col gap-1.5">
        {passkeysSupported() && (
          <Button className="w-full" icon={<Fingerprint />} onClick={passkey}>
            Sign in with a passkey
          </Button>
        )}
        {methods.providers.map((p) => (
          <Button key={p.id} className="w-full" icon={<KeyRound />} onClick={() => auth.signInWith(p.id)}>
            Continue with {p.name}
          </Button>
        ))}
      </div>
    </AuthLayout>
  );
}

function MfaStep({ methods, onSignedIn, onBack }: { methods: string[]; onSignedIn: () => void; onBack: () => void }) {
  const [mode, setMode] = useState<"totp" | "recovery">(methods.includes("totp") ? "totp" : "recovery");
  const [code, setCode] = useState(EMPTY_CODE);
  const [recovery, setRecovery] = useState("");
  const [error, setError] = useState<string>();
  const run = async (f: () => Promise<unknown>) => {
    try {
      await f();
      onSignedIn();
    } catch (err) {
      if (cancelled(err)) return;
      if (err instanceof AuthApiError && (err.status === 429 || err.code === "unauthenticated")) return onBack();
      setError(message(err));
      setCode(EMPTY_CODE());
    }
  };
  return (
    <AuthLayout>
      <Heading title="Two-step verification">{mode === "totp" ? "Enter the 6-digit code from your authenticator app." : "Enter one of the recovery codes you saved."}</Heading>
      <Problem error={error} title="Not verified" />
      <form
        className="flex flex-col gap-2.5"
        onSubmit={(e) => {
          e.preventDefault();
          void run(() => (mode === "totp" ? auth.verifyCode(code.join("")) : auth.useRecoveryCode(recovery)));
        }}
      >
        {mode === "totp" ? (
          <CodeInput value={code} onChange={setCode} />
        ) : (
          <TextField label="Recovery code" mono autoComplete="off" value={recovery} onChange={(e) => setRecovery(e.target.value)} placeholder="xxxxx-xxxxx" />
        )}
        <Button type="submit" variant="primary" icon={<ShieldCheck />} className="w-full" disabled={mode === "totp" ? code.some((d) => !d) : recovery.trim().length < 10}>
          Verify
        </Button>
      </form>
      {methods.includes("passkey") && passkeysSupported() && (
        <>
          <Divider>or</Divider>
          <Button className="w-full" icon={<Fingerprint />} onClick={() => void run(() => auth.signInWithPasskey())}>
            Use a passkey instead
          </Button>
        </>
      )}
      <div className="flex items-center justify-between text-xs">
        <Button size="xs" variant="ghost" icon={<ArrowLeft />} onClick={onBack}>
          Back
        </Button>
        {mode === "totp" ? (
          <Button size="xs" variant="ghost" onClick={() => setMode("recovery")}>
            Use a recovery code
          </Button>
        ) : (
          methods.includes("totp") && (
            <Button size="xs" variant="ghost" onClick={() => setMode("totp")}>
              Use the authenticator app
            </Button>
          )
        )}
      </div>
    </AuthLayout>
  );
}

/** Adds an authenticator app: QR code, the key for typing in, then one code to confirm. */
function TotpSetup({ onAdded, onCancel }: { onAdded: (codes?: string[]) => void; onCancel?: () => void }) {
  const [setup, setSetup] = useState<{ secret: string; uri: string }>();
  const [code, setCode] = useState(EMPTY_CODE);
  const [error, setError] = useState<string>();
  useEffect(() => {
    auth.startTotp().then(setSetup, (err: unknown) => setError(message(err)));
  }, []);
  const confirm = async (e: FormEvent) => {
    e.preventDefault();
    try {
      onAdded((await auth.confirmTotp(code.join(""))).recoveryCodes);
    } catch (err) {
      setError(message(err));
      setCode(EMPTY_CODE());
    }
  };
  return (
    <form className="flex flex-col items-center gap-3" onSubmit={confirm}>
      <p className="text-center text-sm text-fg-muted">Scan this with an authenticator app (1Password, Bitwarden, Google Authenticator, Microsoft Authenticator...).</p>
      {setup ? <QrCode text={setup.uri} /> : <span className="text-sm text-fg-muted">Loading…</span>}
      {setup && (
        <details className="w-full text-xs text-fg-muted">
          <summary>Can't scan it?</summary>
          <p className="mt-1">Enter this key in the app instead:</p>
          <code className="block rounded-md bg-canvas p-2 font-mono text-sm text-fg" style={{ overflowWrap: "anywhere" }}>
            {setup.secret.replace(/(.{4})/g, "$1 ").trim()}
          </code>
        </details>
      )}
      <div className="w-full">
        <Problem error={error} title="Not added" />
      </div>
      <div className="w-full">
        <CodeInput value={code} onChange={setCode} />
      </div>
      <div className="flex w-full gap-2">
        {onCancel && (
          <Button type="button" variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
        )}
        <Button type="submit" variant="primary" style={{ flex: 1 }} disabled={!setup || code.some((d) => !d)}>
          Turn on
        </Button>
      </div>
    </form>
  );
}

function MfaSetup({ productName, onDone, onSignOut }: { productName: string; onDone: () => void; onSignOut: () => void }) {
  const [mode, setMode] = useState<"choose" | "totp">("choose");
  const [codes, setCodes] = useState<string[]>();
  const [error, setError] = useState<string>();
  const added = (c?: string[]) => (c ? setCodes(c) : onDone());
  if (codes) {
    return (
      <AuthLayout wide>
        <Heading title="Two-step verification is on" />
        <RecoveryCodes codes={codes} productName={productName} onDone={onDone} />
      </AuthLayout>
    );
  }
  const passkey = async () => {
    try {
      added((await auth.addPasskey()).recoveryCodes);
    } catch (err) {
      if (!cancelled(err)) setError(message(err));
    }
  };
  return (
    <AuthLayout wide>
      <Heading title="Set up two-step verification">Owners and admins need a second factor besides the password.</Heading>
      {mode === "totp" ? (
        <TotpSetup onAdded={added} onCancel={() => setMode("choose")} />
      ) : (
        <div className="flex flex-col gap-2">
          <Problem error={error} title="Not added" />
          {passkeysSupported() && (
            <Button variant="primary" className="w-full" icon={<Fingerprint />} onClick={passkey}>
              Add a passkey
            </Button>
          )}
          <Button className="w-full" icon={<Smartphone />} onClick={() => setMode("totp")}>
            Use an authenticator app
          </Button>
          <Button size="xs" variant="ghost" onClick={onSignOut}>
            Sign out
          </Button>
        </div>
      )}
    </AuthLayout>
  );
}

function Setup({ token, onDone }: { token: string; onDone: () => void }) {
  const productName = useProductName();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string>();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await auth.setup({ token, name, email, password });
      onDone();
    } catch (err) {
      setError(message(err));
    }
  };
  return (
    <AuthLayout>
      <Heading title={`Set up ${productName}`}>Create the owner account. You can invite others afterwards.</Heading>
      <Problem error={error} title="Not created" />
      <form className="flex flex-col gap-2.5" onSubmit={submit}>
        <TextField label="Name" autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} />
        <TextField label="Email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
        <PasswordFields password={password} setPassword={setPassword} confirm={confirm} setConfirm={setConfirm} />
        <Button type="submit" variant="primary" className="w-full" disabled={!name.trim() || !email || !passwordOk(password, confirm)}>
          Create owner
        </Button>
      </form>
    </AuthLayout>
  );
}

function SetupPending() {
  const name = useProductName();
  return (
    <AuthLayout>
      <Heading title={`${name} is not set up yet`}>Open the setup link printed in the product's log when it started. Restarting prints a new one.</Heading>
    </AuthLayout>
  );
}

function PasswordLink({ token, onDone, onInvalid }: { token: string; onDone: () => void; onInvalid: (error: string) => void }) {
  const [info, setInfo] = useState<{ kind: "invite" | "reset"; email: string; name: string; productName: string }>();
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string>();
  useEffect(() => {
    auth.link(token).then(
      (i) => {
        setInfo(i);
        setName(i.name === i.email ? "" : i.name);
      },
      (err: unknown) => onInvalid(message(err)),
    );
  }, [token, onInvalid]);
  if (!info) return <AuthLayout>{null}</AuthLayout>;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await auth.acceptLink(token, password, info.kind === "invite" ? name : undefined);
      onDone();
    } catch (err) {
      setError(message(err));
    }
  };
  return (
    <AuthLayout>
      <Heading title={info.kind === "invite" ? `Join ${info.productName}` : "Choose a new password"}>{info.email}</Heading>
      <Problem error={error} title="Not saved" />
      <form className="flex flex-col gap-2.5" onSubmit={submit}>
        <input type="email" autoComplete="username" value={info.email} readOnly hidden />
        {info.kind === "invite" && <TextField label="Your name" autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} />}
        <PasswordFields password={password} setPassword={setPassword} confirm={confirm} setConfirm={setConfirm} />
        <Button type="submit" variant="primary" className="w-full" disabled={!passwordOk(password, confirm) || (info.kind === "invite" && !name.trim())}>
          {info.kind === "invite" ? "Join" : "Save password"}
        </Button>
      </form>
    </AuthLayout>
  );
}

type Stage =
  | { k: "loading" }
  | { k: "setup"; token: string }
  | { k: "setup-pending" }
  | { k: "link"; token: string }
  | { k: "sign-in"; error?: string }
  | { k: "mfa"; methods: string[] }
  | { k: "mfa-setup"; me: Me }
  | { k: "in"; me: Me };

/**
 * Shows the product only to signed-in people: first-start setup, invitations and password links, sign-in with a
 * password, passkey or identity provider, the second step, and setting up a second factor when an owner or admin
 * has none. Inside, `useAuth()` gives the person and their role.
 */
export function AuthGate({ children, product }: { children: ReactNode; /** The product's name, as in "Sign in to OpenAsy Vulnerabilities". */ product?: string }) {
  return (
    <ProductContext.Provider value={product}>
      <Gate>{children}</Gate>
    </ProductContext.Provider>
  );
}

function Gate({ children }: { children: ReactNode }) {
  const name = useProductName();
  const [stage, setStage] = useState<Stage>({ k: "loading" });
  const [methods, setMethods] = useState<Methods>();
  const [loadError, setLoadError] = useState<string>();

  const load = useCallback(async (error?: string) => {
    try {
      const me = await auth.me();
      setStage(me.mfaSetupRequired ? { k: "mfa-setup", me } : { k: "in", me });
    } catch (err) {
      if (!(err instanceof AuthApiError) || err.status !== 401) throw err;
      const m = await auth.methods();
      setMethods(m);
      setStage(m.setupRequired ? { k: "setup-pending" } : { k: "sign-in", error });
    }
  }, []);

  useEffect(() => {
    const params = takeAuthParams();
    auth.methods().then(
      (m) => {
        setMethods(m);
        if (params.setup && m.setupRequired) setStage({ k: "setup", token: params.setup });
        else if (params.link) setStage({ k: "link", token: params.link });
        else load(params.error).catch((err: unknown) => setLoadError(message(err)));
      },
      (err: unknown) => setLoadError(message(err)),
    );
  }, [load]);

  const signOut = useCallback(async () => {
    await auth.signOut().catch(() => {});
    setStage({ k: "sign-in" });
  }, []);
  const reload = useCallback(() => load().catch((err: unknown) => setLoadError(message(err))), [load]);
  const onInvalidLink = useCallback((error: string) => setStage({ k: "sign-in", error }), []);

  if (loadError) {
    return (
      <AuthLayout>
        <Problem error={loadError} title={`${name} is not reachable`} />
        <Button onClick={() => location.reload()}>Try again</Button>
      </AuthLayout>
    );
  }
  switch (stage.k) {
    case "loading":
      return null;
    case "setup":
      return <Setup token={stage.token} onDone={reload} />;
    case "setup-pending":
      return <SetupPending />;
    case "link":
      return <PasswordLink token={stage.token} onDone={reload} onInvalid={onInvalidLink} />;
    case "sign-in":
      return <SignIn methods={methods!} initialError={stage.error} onSignedIn={reload} onMfa={(m) => setStage({ k: "mfa", methods: m })} />;
    case "mfa":
      return <MfaStep methods={stage.methods} onSignedIn={reload} onBack={() => setStage({ k: "sign-in" })} />;
    case "mfa-setup":
      return <MfaSetup productName={name} onDone={reload} onSignOut={signOut} />;
    case "in":
      return (
        <AuthContext.Provider
          value={{
            me: stage.me,
            can: (role) => RANK.indexOf(stage.me.user.role) >= RANK.indexOf(role),
            refresh: reload,
            signOut,
            expired: () => setStage({ k: "sign-in", error: "Your session ended. Sign in again." }),
          }}
        >
          {children}
        </AuthContext.Provider>
      );
  }
}

// ---- Settings -----------------------------------------------------------------------------------------------------

const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "never");

function useList<T>(load: () => Promise<T[]>) {
  const [rows, setRows] = useState<T[]>();
  const [error, setError] = useState<string>();
  const reload = useCallback(() => load().then(setRows, (err: unknown) => setError(message(err))), [load]);
  useEffect(() => {
    void reload();
  }, [reload]);
  return { rows, error, setError, reload };
}

function Table({ label, head, children }: { label: string; head: string[]; children: ReactNode }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table aria-label={label} className="w-full text-left text-sm" style={{ borderCollapse: "collapse" }}>
        <thead>
          <tr className="border-b border-line text-xs text-fg-muted">
            {head.map((h) => (
              <th key={h} scope="col" className="px-2 py-1.5 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

const Cell = ({ children, mono = false }: { children: ReactNode; mono?: boolean }) => <td className={`border-b border-line px-2 py-1.5 align-middle ${mono ? "font-mono text-xs" : ""}`}>{children}</td>;

/** The signed-in person: name, password, second factors, recovery codes and sessions. */
export function AccountSettings() {
  const { me, refresh } = useAuth();
  const productName = useProductName();
  const [name, setName] = useState(me.user.name);
  const [current, setCurrent] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [addingTotp, setAddingTotp] = useState(false);
  const [codes, setCodes] = useState<string[]>();
  const [note, setNote] = useState<string>();
  const [error, setError] = useState<string>();
  const sessions = useList<Session>(auth.sessions);

  const act = async (f: () => Promise<unknown>, done?: string) => {
    setError(undefined);
    try {
      await f();
      setNote(done);
      await refresh();
    } catch (err) {
      if (!cancelled(err)) setError(message(err));
    }
  };

  if (codes) {
    return (
      <Panel title="Recovery codes">
        <div style={{ maxWidth: 420 }}>
          <RecoveryCodes codes={codes} productName={productName} onDone={() => setCodes(undefined)} />
        </div>
      </Panel>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {note && (
        <Callout tone="success" title={note} onDismiss={() => setNote(undefined)}>
          {null}
        </Callout>
      )}
      <Problem error={error} />
      <Panel title="Profile" description={`${me.user.email} · ${ROLE_NAMES[me.user.role]}`}>
        <form
          className="flex flex-col gap-2.5"
          style={{ maxWidth: 420 }}
          onSubmit={(e) => {
            e.preventDefault();
            void act(() => auth.rename(name.trim()), "Name saved");
          }}
        >
          <TextField label="Name" autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} />
          <div>
            <Button type="submit" size="sm" disabled={!name.trim() || name.trim() === me.user.name}>
              Save
            </Button>
          </div>
        </form>
      </Panel>

      {me.hasPassword && (
        <Panel title="Password" description="Changing it signs you out everywhere else.">
          <form
            className="flex flex-col gap-2.5"
            style={{ maxWidth: 420 }}
            onSubmit={(e) => {
              e.preventDefault();
              void act(async () => {
                await auth.changePassword(current, password);
                setCurrent("");
                setPassword("");
                setConfirm("");
                void sessions.reload();
              }, "Password changed");
            }}
          >
            <TextField label="Current password" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
            <PasswordFields password={password} setPassword={setPassword} confirm={confirm} setConfirm={setConfirm} />
            <div>
              <Button type="submit" size="sm" disabled={!current || !passwordOk(password, confirm)}>
                Change password
              </Button>
            </div>
          </form>
        </Panel>
      )}

      <Panel title="Two-step verification" description={me.user.mfa.totp || me.passkeys.length ? `On · ${me.recoveryCodesLeft} recovery codes left` : "Off"}>
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="flex items-center gap-2 text-sm">
              <Smartphone className="h-4 w-4" aria-hidden /> Authenticator app {me.user.mfa.totp ? <Badge tone="success">On</Badge> : <Badge>Off</Badge>}
            </span>
            {me.user.mfa.totp ? (
              <Button size="sm" variant="ghost" icon={<Trash2 />} onClick={() => void act(auth.removeTotp, "Authenticator app removed")}>
                Remove
              </Button>
            ) : (
              !addingTotp && (
                <Button size="sm" icon={<Plus />} onClick={() => setAddingTotp(true)}>
                  Add
                </Button>
              )
            )}
          </div>
          {addingTotp && (
            <div style={{ maxWidth: 380 }}>
              <TotpSetup
                onCancel={() => setAddingTotp(false)}
                onAdded={(c) => {
                  setAddingTotp(false);
                  if (c) setCodes(c);
                  void refresh();
                }}
              />
            </div>
          )}
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="flex items-center gap-2 text-sm">
              <Fingerprint className="h-4 w-4" aria-hidden /> Passkeys {me.passkeys.length ? <Badge tone="success">{me.passkeys.length}</Badge> : <Badge>None</Badge>}
            </span>
            {passkeysSupported() && (
              <Button
                size="sm"
                icon={<Plus />}
                onClick={() =>
                  void act(async () => {
                    const r = await auth.addPasskey(deviceName(navigator.userAgent));
                    if (r.recoveryCodes) setCodes(r.recoveryCodes);
                  }, "Passkey added")
                }
              >
                Add
              </Button>
            )}
          </div>
          {me.passkeys.length > 0 && (
            <Table label="Passkeys" head={["Name", "Added", "Last used", ""]}>
              {me.passkeys.map((k) => (
                <tr key={k.id}>
                  <Cell>{k.name}</Cell>
                  <Cell>{when(k.createdAt)}</Cell>
                  <Cell>{when(k.lastUsedAt)}</Cell>
                  <Cell>
                    <Button size="xs" variant="ghost" icon={<Trash2 />} onClick={() => void act(() => auth.removePasskey(k.id), "Passkey removed")}>
                      Remove
                    </Button>
                  </Cell>
                </tr>
              ))}
            </Table>
          )}
          {(me.user.mfa.totp || me.passkeys.length > 0) && (
            <div>
              <Button size="sm" onClick={() => void act(async () => setCodes(await auth.newRecoveryCodes()))}>
                New recovery codes
              </Button>
            </div>
          )}
        </div>
      </Panel>

      <Panel title="Sessions" description="Where you are signed in. Sign out a session you do not recognise.">
        <Problem error={sessions.error} />
        <Table label="Sessions" head={["Device", "Address", "Signed in", "Last active", ""]}>
          {(sessions.rows ?? []).map((s) => (
            <tr key={s.id}>
              <Cell>
                <span title={s.userAgent}>{deviceName(s.userAgent)}</span> {s.current && <Badge tone="info">This browser</Badge>}
              </Cell>
              <Cell mono>{s.ip}</Cell>
              <Cell>{when(s.createdAt)}</Cell>
              <Cell>{when(s.lastSeenAt)}</Cell>
              <Cell>
                {!s.current && (
                  <Button size="xs" variant="ghost" onClick={() => void act(() => auth.revokeSession(s.id).then(sessions.reload), "Session signed out")}>
                    Sign out
                  </Button>
                )}
              </Cell>
            </tr>
          ))}
        </Table>
      </Panel>
    </div>
  );
}

function deviceName(ua: string) {
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /Windows/.test(ua) ? "Windows" : /Mac OS X/.test(ua) ? "macOS" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}

function LinkBox({ title, link, expiresAt, onDone }: { title: string; link: string; expiresAt: string; onDone: () => void }) {
  return (
    <Callout tone="info" title={title} onDismiss={onDone}>
      <span className="flex flex-col gap-2">
        <span>Send this link to them yourself; it works once, until {when(expiresAt)}.</span>
        <code className="block rounded-md bg-canvas p-2 font-mono text-xs text-fg" style={{ overflowWrap: "anywhere" }}>
          {link}
        </code>
        <span>
          <Button size="xs" icon={<Copy />} onClick={() => copy(link)}>
            Copy link
          </Button>
        </span>
      </span>
    </Callout>
  );
}

/** Settings → Members: invite, change roles, disable, reset and remove (admins; owners for owners). */
export function MembersSettings() {
  const { me } = useAuth();
  const members = useList<Member>(auth.members);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [link, setLink] = useState<{ title: string; link: string; expiresAt: string }>();
  const isOwner = me.user.role === "owner";
  const roles = (isOwner ? RANK : RANK.filter((r) => r !== "owner")).slice().reverse();
  const roleOptions = roles.map((r) => ({ value: r, label: ROLE_NAMES[r] }));

  const act = async (f: () => Promise<unknown>) => {
    members.setError(undefined);
    try {
      await f();
      await members.reload();
    } catch (err) {
      members.setError(message(err));
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <Panel title="Invite" description="New members get a link to choose their password. People from an identity provider are linked by their verified email.">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void act(async () => {
              const r = await auth.invite({ email, name: name || undefined, role });
              setLink({ title: `Invitation for ${r.member.email}`, link: r.link, expiresAt: r.linkExpiresAt });
              setEmail("");
              setName("");
            });
          }}
        >
          <TextField label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <SelectField label="Role" value={role} onChange={(e) => setRole(e.target.value as Role)} options={roleOptions} />
          <Button type="submit" variant="primary" icon={<Plus />} disabled={!email.includes("@")}>
            Invite
          </Button>
        </form>
      </Panel>
      {link && <LinkBox {...link} onDone={() => setLink(undefined)} />}
      <Problem error={members.error} />
      <Panel title="Members" flush>
        <Table label="Members" head={["Name", "Email", "Role", "Status", "Second factor", "Last sign-in", ""]}>
          {(members.rows ?? []).map((m) => {
            const manageable = m.id !== me.user.id && (isOwner || m.role !== "owner");
            return (
              <tr key={m.id}>
                <Cell>{m.name}</Cell>
                <Cell mono>{m.email}</Cell>
                <Cell>
                  {manageable ? (
                    <SelectField aria-label={`Role of ${m.email}`} value={m.role} onChange={(e) => void act(() => auth.updateMember(m.id, { role: e.target.value as Role }))} options={roleOptions} />
                  ) : (
                    ROLE_NAMES[m.role]
                  )}
                </Cell>
                <Cell>
                  <Badge tone={m.status === "active" ? "success" : m.status === "invited" ? "info" : "neutral"}>{m.status}</Badge>
                </Cell>
                <Cell>{m.providers.length ? m.providers.join(", ") : m.mfa.totp || m.mfa.passkeys ? "On" : "Off"}</Cell>
                <Cell>{when(m.lastSignInAt)}</Cell>
                <Cell>
                  {manageable && (
                    <span className="flex gap-1">
                      <Button
                        size="xs"
                        variant="ghost"
                        onClick={() =>
                          void act(async () => {
                            const r = await auth.resetMember(m.id, { mfa: confirm(`Also remove ${m.email}'s second factors? Choose Cancel to keep them.`) });
                            setLink({ title: `Password link for ${m.email}`, link: r.link, expiresAt: r.linkExpiresAt });
                          })
                        }
                      >
                        {m.status === "invited" ? "New link" : "Reset"}
                      </Button>
                      {m.status !== "invited" && (
                        <Button size="xs" variant="ghost" onClick={() => void act(() => auth.updateMember(m.id, { status: m.status === "active" ? "disabled" : "active" }))}>
                          {m.status === "active" ? "Disable" : "Enable"}
                        </Button>
                      )}
                      <Button size="xs" variant="ghost" icon={<Trash2 />} onClick={() => confirm(`Remove ${m.email}?`) && void act(() => auth.removeMember(m.id))}>
                        Remove
                      </Button>
                    </span>
                  )}
                </Cell>
              </tr>
            );
          })}
        </Table>
      </Panel>
    </div>
  );
}

/** Settings → API tokens: for scripts and CI. One role each, always an expiry, the secret shown once. */
export function TokensSettings() {
  const { me } = useAuth();
  const tokens = useList<ApiToken>(auth.tokens);
  const [name, setName] = useState("");
  const [role, setRole] = useState<ApiToken["role"]>("viewer");
  const [days, setDays] = useState("90");
  const [created, setCreated] = useState<{ name: string; token: string }>();
  const roles = (["admin", "editor", "viewer"] as const).filter((r) => RANK.indexOf(me.user.role) >= RANK.indexOf(r));

  const act = async (f: () => Promise<unknown>) => {
    tokens.setError(undefined);
    try {
      await f();
      await tokens.reload();
    } catch (err) {
      tokens.setError(message(err));
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <Panel title="New token" description="Send it as Authorization: Bearer <token>. It can do what its role allows in this product only.">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void act(async () => {
              const r = await auth.createToken({ name, role, expiresInDays: Number(days) });
              setCreated({ name: r.name, token: r.token });
              setName("");
            });
          }}
        >
          <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="CI pipeline" />
          <SelectField label="Role" value={role} onChange={(e) => setRole(e.target.value as ApiToken["role"])} options={roles.map((r) => ({ value: r, label: ROLE_NAMES[r] }))} />
          <SelectField
            label="Expires"
            value={days}
            onChange={(e) => setDays(e.target.value)}
            options={[
              { value: "7", label: "In 7 days" },
              { value: "30", label: "In 30 days" },
              { value: "90", label: "In 90 days" },
              { value: "366", label: "In a year" },
            ]}
          />
          <Button type="submit" variant="primary" icon={<Plus />} disabled={!name.trim()}>
            Create
          </Button>
        </form>
      </Panel>
      {created && (
        <Callout tone="warning" title={`Copy the token for ${created.name} now`} onDismiss={() => setCreated(undefined)}>
          <span className="flex flex-col gap-2">
            <span>It is not shown again.</span>
            <code className="block rounded-md bg-canvas p-2 font-mono text-xs text-fg" style={{ overflowWrap: "anywhere" }}>
              {created.token}
            </code>
            <span>
              <Button size="xs" icon={<Copy />} onClick={() => copy(created.token)}>
                Copy token
              </Button>
            </span>
          </span>
        </Callout>
      )}
      <Problem error={tokens.error} />
      <Panel title="Tokens" flush>
        <Table label="API tokens" head={["Name", "Role", "Created by", "Expires", "Last used", ""]}>
          {(tokens.rows ?? []).map((t) => (
            <tr key={t.id}>
              <Cell>{t.name}</Cell>
              <Cell>{ROLE_NAMES[t.role]}</Cell>
              <Cell mono>{t.createdBy ?? "removed member"}</Cell>
              <Cell>{t.expired ? <Badge tone="danger">Expired</Badge> : when(t.expiresAt)}</Cell>
              <Cell>{when(t.lastUsedAt)}</Cell>
              <Cell>
                <Button size="xs" variant="ghost" icon={<Trash2 />} onClick={() => confirm(`Revoke ${t.name}? Anything using it stops working.`) && void act(() => auth.revokeToken(t.id))}>
                  Revoke
                </Button>
              </Cell>
            </tr>
          ))}
        </Table>
      </Panel>
    </div>
  );
}
