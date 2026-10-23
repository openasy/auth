// Screens for @openasy/auth, built from @openasy/ui: the sign-in gate around a product's UI, and the Account, Members
// and API tokens settings. They follow the Identity/Sign-in stories in the ui Storybook.
import { Badge, Button, Callout, Panel, SelectField, Switch, TextField, useBrand, useMessages } from "@openasy/ui";
import { ArrowLeft, Copy, Download, Fingerprint, KeyRound, LogIn, Pencil, Plus, ShieldCheck, Smartphone, Trash2 } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ClipboardEvent, type FormEvent, type KeyboardEvent, type ReactNode } from "react";
import { encode } from "uqr";
import { auth, AuthApiError, passkeysSupported, signedOut, takeAuthParams, type ApiToken, type Me, type Member, type Methods, type Provider, type ProviderChange, type Role, type Session } from "./client.ts";
import { MESSAGES } from "./messages.ts";
import { PRESETS } from "./presets.ts";

export { auth, AuthApiError, type Me, type Member, type Provider, type Role } from "./client.ts";

/** `t(key, vars)` in the BrandProvider locale. */
const useT = () => useMessages(MESSAGES);
type T = ReturnType<typeof useT>;
const roleName = (t: T, role: Role) => t(`role.${role}`);
const RANK: Role[] = ["user", "viewer", "editor", "admin", "owner"];
const message = (err: unknown) => (err instanceof Error ? err.message : String(err));
/** The person closed the browser's passkey prompt: not an error worth showing. */
const cancelled = (err: unknown) => err instanceof Error && (err.name === "NotAllowedError" || err.name === "AbortError");

// ---- Context ------------------------------------------------------------------------------------------------------

interface AuthContextValue {
  me: Me;
  /** Whether this product has members with the user role (Identity's directory). */
  users: boolean;
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
  const t = useT();
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
      {!brand.hidePoweredBy && <footer className="text-xs text-fg-muted">{t("common.poweredBy")}</footer>}
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

function Problem({ error, title }: { error?: string; title?: string }) {
  const t = useT();
  return error ? (
    <Callout tone="danger" title={title ?? t("common.somethingWrong")}>
      {error}
    </Callout>
  ) : null;
}

/** Six boxes for a TOTP code; typing, pasting, backspace and arrow keys move between them. */
function CodeInput({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const t = useT();
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
      <legend className="mb-1.5 text-xs font-medium text-fg">{t("code.legend")}</legend>
      <div className="flex justify-between gap-1.5">
        {Array.from({ length: 6 }, (_, i) => (
          <input
            key={i}
            ref={(el) => {
              refs.current[i] = el;
            }}
            aria-label={t("code.digit", { n: i + 1 })}
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
  const t = useT();
  const { data } = encode(text, { border: 2 });
  const n = data.length;
  let d = "";
  data.forEach((row, y) => row.forEach((on, x) => on && (d += `M${x} ${y}h1v1h-1z`)));
  return (
    <svg role="img" aria-label={t("code.qr")} viewBox={`0 0 ${n} ${n}`} width={size} height={size} shapeRendering="crispEdges" className="rounded-md">
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
  const t = useT();
  const [saved, setSaved] = useState(false);
  const text = `${t("recovery.file", { product: productName })}\n\n${codes.join("\n")}\n`;
  return (
    <div className="flex flex-col gap-3">
      <Callout tone="warning" title={t("recovery.saveTitle")}>
        {t("recovery.saveBody")}
      </Callout>
      <ul aria-label={t("recovery.codes")} className="grid grid-cols-2 gap-1.5 rounded-md border border-line bg-canvas p-3 font-mono text-sm" style={{ listStyle: "none", margin: 0 }}>
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <div className="flex gap-2">
        <Button size="sm" icon={<Copy />} onClick={() => copy(codes.join("\n"))}>
          {t("common.copy")}
        </Button>
        <Button size="sm" icon={<Download />} onClick={() => download(`${productName.toLowerCase().replace(/\W+/g, "-")}-${t("recovery.fileName")}.txt`, text)}>
          {t("common.download")}
        </Button>
      </div>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
        {t("recovery.saved")}
      </label>
      <Button variant="primary" disabled={!saved} onClick={onDone}>
        {t("common.continue")}
      </Button>
    </div>
  );
}

// ---- Sign-in screens ----------------------------------------------------------------------------------------------

function PasswordFields({ password, setPassword, confirm, setConfirm }: { password: string; setPassword: (v: string) => void; confirm: string; setConfirm: (v: string) => void }) {
  const t = useT();
  return (
    <>
      <TextField label={t("password.label")} type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} hint={t("password.hint")} />
      <TextField
        label={t("password.repeat")}
        type="password"
        autoComplete="new-password"
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
        error={confirm && confirm !== password ? t("password.differ") : undefined}
      />
    </>
  );
}

const passwordOk = (p: string, c: string) => p.length >= 12 && p === c;

function SignIn({ methods, initialError, onSignedIn, onMfa }: { methods: Methods; initialError?: string; onSignedIn: () => void; onMfa: (methods: string[]) => void }) {
  const t = useT();
  const name = useProductName();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(initialError);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!email || !password) return setError(t("signIn.enterBoth"));
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
      <h1 className="text-center text-lg font-semibold text-fg">{t("signIn.title", { product: name })}</h1>
      <Problem error={error} title={t("signIn.failed")} />
      {methods.passwords && (
        <form className="flex flex-col gap-2.5" onSubmit={submit} noValidate>
          <TextField label={t("common.email")} type="email" autoComplete="username webauthn" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} />
          <TextField
            label={t("password.label")}
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            hint={t("signIn.forgot")}
          />
          <Button type="submit" variant="primary" icon={<LogIn />} className="w-full" loading={busy}>
            {t("signIn.submit")}
          </Button>
        </form>
      )}
      {(methods.providers.length > 0 || passkeysSupported()) && methods.passwords && <Divider>{t("common.or")}</Divider>}
      <div className="flex flex-col gap-1.5">
        {passkeysSupported() && (
          <Button className="w-full" icon={<Fingerprint />} onClick={passkey}>
            {t("signIn.passkey")}
          </Button>
        )}
        {methods.providers.map((p) => (
          <Button key={p.id} className="w-full" icon={<KeyRound />} onClick={() => auth.signInWith(p.id)}>
            {t("common.continueWith", { provider: p.name })}
          </Button>
        ))}
      </div>
    </AuthLayout>
  );
}

function MfaStep({ methods, onSignedIn, onBack }: { methods: string[]; onSignedIn: () => void; onBack: () => void }) {
  const t = useT();
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
      <Heading title={t("mfa.title")}>{mode === "totp" ? t("mfa.enterCode") : t("mfa.enterRecovery")}</Heading>
      <Problem error={error} title={t("mfa.notVerified")} />
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
          <TextField label={t("mfa.recoveryCode")} mono autoComplete="off" value={recovery} onChange={(e) => setRecovery(e.target.value)} placeholder="xxxxx-xxxxx" />
        )}
        <Button type="submit" variant="primary" icon={<ShieldCheck />} className="w-full" disabled={mode === "totp" ? code.some((d) => !d) : recovery.trim().length < 10}>
          {t("mfa.verify")}
        </Button>
      </form>
      {methods.includes("passkey") && passkeysSupported() && (
        <>
          <Divider>{t("common.or")}</Divider>
          <Button className="w-full" icon={<Fingerprint />} onClick={() => void run(() => auth.signInWithPasskey())}>
            {t("mfa.usePasskey")}
          </Button>
        </>
      )}
      <div className="flex items-center justify-between text-xs">
        <Button size="xs" variant="ghost" icon={<ArrowLeft />} onClick={onBack}>
          {t("common.back")}
        </Button>
        {mode === "totp" ? (
          <Button size="xs" variant="ghost" onClick={() => setMode("recovery")}>
            {t("mfa.useRecovery")}
          </Button>
        ) : (
          methods.includes("totp") && (
            <Button size="xs" variant="ghost" onClick={() => setMode("totp")}>
              {t("mfa.useApp")}
            </Button>
          )
        )}
      </div>
    </AuthLayout>
  );
}

/** Adds an authenticator app: QR code, the key for typing in, then one code to confirm. */
function TotpSetup({ onAdded, onCancel }: { onAdded: (codes?: string[]) => void; onCancel?: () => void }) {
  const t = useT();
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
      <p className="text-center text-sm text-fg-muted">{t("mfa.scan")}</p>
      {setup ? <QrCode text={setup.uri} /> : <span className="text-sm text-fg-muted">{t("common.loading")}</span>}
      {setup && (
        <details className="w-full text-xs text-fg-muted">
          <summary>{t("mfa.cantScan")}</summary>
          <p className="mt-1">{t("mfa.enterKey")}</p>
          <code className="block rounded-md bg-canvas p-2 font-mono text-sm text-fg" style={{ overflowWrap: "anywhere" }}>
            {setup.secret.replace(/(.{4})/g, "$1 ").trim()}
          </code>
        </details>
      )}
      <div className="w-full">
        <Problem error={error} title={t("common.notAdded")} />
      </div>
      <div className="w-full">
        <CodeInput value={code} onChange={setCode} />
      </div>
      <div className="flex w-full gap-2">
        {onCancel && (
          <Button type="button" variant="ghost" onClick={onCancel}>
            {t("common.cancel")}
          </Button>
        )}
        <Button type="submit" variant="primary" style={{ flex: 1 }} disabled={!setup || code.some((d) => !d)}>
          {t("mfa.turnOn")}
        </Button>
      </div>
    </form>
  );
}

function MfaSetup({ productName, onDone, onSignOut }: { productName: string; onDone: () => void; onSignOut: () => void }) {
  const t = useT();
  const [mode, setMode] = useState<"choose" | "totp">("choose");
  const [codes, setCodes] = useState<string[]>();
  const [error, setError] = useState<string>();
  const added = (c?: string[]) => (c ? setCodes(c) : onDone());
  if (codes) {
    return (
      <AuthLayout wide>
        <Heading title={t("mfa.isOn")} />
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
      <Heading title={t("mfa.setUp")}>{t("mfa.required")}</Heading>
      {mode === "totp" ? (
        <TotpSetup onAdded={added} onCancel={() => setMode("choose")} />
      ) : (
        <div className="flex flex-col gap-2">
          <Problem error={error} title={t("common.notAdded")} />
          {passkeysSupported() && (
            <Button variant="primary" className="w-full" icon={<Fingerprint />} onClick={passkey}>
              {t("mfa.addPasskey")}
            </Button>
          )}
          <Button className="w-full" icon={<Smartphone />} onClick={() => setMode("totp")}>
            {t("mfa.useAnApp")}
          </Button>
          <Button size="xs" variant="ghost" onClick={onSignOut}>
            {t("common.signOut")}
          </Button>
        </div>
      )}
    </AuthLayout>
  );
}

function Setup({ token, methods, onDone }: { token: string; methods: Methods; onDone: () => void }) {
  const t = useT();
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
      <Heading title={t("setup.title", { product: productName })}>{methods.passwords ? t("setup.withPassword") : t("setup.withProvider")}</Heading>
      <Problem error={error} title={t("setup.notCreated")} />
      {methods.passwords && (
        <form className="flex flex-col gap-2.5" onSubmit={submit}>
          <TextField label={t("common.name")} autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} />
          <TextField label={t("common.email")} type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
          <PasswordFields password={password} setPassword={setPassword} confirm={confirm} setConfirm={setConfirm} />
          <Button type="submit" variant="primary" className="w-full" disabled={!name.trim() || !email || !passwordOk(password, confirm)}>
            {t("setup.createOwner")}
          </Button>
        </form>
      )}
      {methods.passwords && methods.providers.length > 0 && <Divider>{t("common.or")}</Divider>}
      {methods.providers.length > 0 && (
        <div className="flex flex-col gap-1.5">
          {methods.providers.map((p) => (
            <Button key={p.id} className="w-full" variant={methods.passwords ? "secondary" : "primary"} icon={<KeyRound />} onClick={() => auth.setupWith(p.id, token)}>
              {t("common.continueWith", { provider: p.name })}
            </Button>
          ))}
        </div>
      )}
    </AuthLayout>
  );
}

function SetupPending() {
  const t = useT();
  const name = useProductName();
  return (
    <AuthLayout>
      <Heading title={t("setup.pending", { product: name })}>{t("setup.pendingBody")}</Heading>
    </AuthLayout>
  );
}

function PasswordLink({ token, onDone, onInvalid }: { token: string; onDone: () => void; onInvalid: (error: string) => void }) {
  const t = useT();
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
      <Heading title={info.kind === "invite" ? t("link.join", { product: info.productName }) : t("link.newPassword")}>{info.email}</Heading>
      <Problem error={error} title={t("common.notSaved")} />
      <form className="flex flex-col gap-2.5" onSubmit={submit}>
        <input type="email" autoComplete="username" value={info.email} readOnly hidden />
        {info.kind === "invite" && <TextField label={t("link.yourName")} autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} />}
        <PasswordFields password={password} setPassword={setPassword} confirm={confirm} setConfirm={setConfirm} />
        <Button type="submit" variant="primary" className="w-full" disabled={!passwordOk(password, confirm) || (info.kind === "invite" && !name.trim())}>
          {info.kind === "invite" ? t("link.joinButton") : t("link.savePassword")}
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
  // `manual`: the person is choosing how to sign in here, so the screen does not go straight to a provider.
  // `expired`: the error is a session that ended, which a provider whose own session still runs fixes at once.
  | { k: "sign-in"; error?: string; manual?: boolean; expired?: boolean }
  | { k: "mfa"; methods: string[] }
  | { k: "mfa-setup"; me: Me }
  | { k: "in"; me: Me };

/**
 * Shows the product only to signed-in people: first-start setup, invitations and password links, sign-in with a
 * password, passkey or identity provider, the second step, and setting up a second factor when an owner or admin
 * has none. With a provider set to go straight to, the sign-in screen is that provider's, except after signing out,
 * after a failed sign-in and with ?local=1. Inside, `useAuth()` gives the person and their role.
 */
export function AuthGate({ children, product }: { children: ReactNode; /** The product's name, as in "Sign in to OpenAsy Vulnerabilities". */ product?: string }) {
  return (
    <ProductContext.Provider value={product}>
      <Gate>{children}</Gate>
    </ProductContext.Provider>
  );
}

function Gate({ children }: { children: ReactNode }) {
  const t = useT();
  const name = useProductName();
  const [stage, setStage] = useState<Stage>({ k: "loading" });
  const [methods, setMethods] = useState<Methods>();
  const [loadError, setLoadError] = useState<string>();
  const [local, setLocal] = useState(false);

  const load = useCallback(async (error?: string) => {
    try {
      const me = await auth.me();
      signedOut.set(false);
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
    setLocal(params.local);
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
    signedOut.set(true);
    setStage({ k: "sign-in", manual: true });
  }, []);
  const reload = useCallback(() => load().catch((err: unknown) => setLoadError(message(err))), [load]);
  const onInvalidLink = useCallback((error: string) => setStage({ k: "sign-in", error }), []);

  const straightTo =
    stage.k === "sign-in" && !stage.manual && (!stage.error || stage.expired) && !local && !signedOut.get() ? methods?.providers.find((p) => p.id === methods.autoRedirect) : undefined;
  useEffect(() => {
    if (straightTo) auth.signInWith(straightTo.id);
  }, [straightTo]);

  if (loadError) {
    return (
      <AuthLayout>
        <Problem error={loadError} title={t("signIn.unreachable", { product: name })} />
        <Button onClick={() => location.reload()}>{t("signIn.tryAgain")}</Button>
      </AuthLayout>
    );
  }
  switch (stage.k) {
    case "loading":
      return null;
    case "setup":
      return <Setup token={stage.token} methods={methods!} onDone={reload} />;
    case "setup-pending":
      return <SetupPending />;
    case "link":
      return <PasswordLink token={stage.token} onDone={reload} onInvalid={onInvalidLink} />;
    case "sign-in":
      if (straightTo) {
        return (
          <AuthLayout>
            <p role="status" className="text-center text-sm text-fg-muted">
              {t("signIn.through", { provider: straightTo.name })}
            </p>
          </AuthLayout>
        );
      }
      return <SignIn methods={methods!} initialError={stage.error} onSignedIn={reload} onMfa={(m) => setStage({ k: "mfa", methods: m })} />;
    case "mfa":
      return <MfaStep methods={stage.methods} onSignedIn={reload} onBack={() => setStage({ k: "sign-in", manual: true })} />;
    case "mfa-setup":
      return <MfaSetup productName={name} onDone={reload} onSignOut={signOut} />;
    case "in":
      return (
        <AuthContext.Provider
          value={{
            me: stage.me,
            users: methods?.users ?? false,
            can: (role) => RANK.indexOf(stage.me.user.role) >= RANK.indexOf(role),
            refresh: reload,
            signOut,
            expired: () => setStage({ k: "sign-in", error: t("signIn.sessionEnded"), expired: true }),
          }}
        >
          {children}
        </AuthContext.Provider>
      );
  }
}

// ---- Settings -----------------------------------------------------------------------------------------------------

const when = (t: T, iso: string | null) => (iso ? new Date(iso).toLocaleString() : t("common.never"));

function useList<T>(load: () => Promise<T[]>) {
  const [rows, setRows] = useState<T[]>();
  const [error, setError] = useState<string>();
  const reload = useCallback(() => load().then(setRows, (err: unknown) => setError(message(err))), [load]);
  useEffect(() => {
    void reload();
  }, [reload]);
  return { rows, error, setError, reload };
}

/** `minWidth` keeps wide rows readable on a phone: the table scrolls sideways instead of squeezing every column. */
function Table({ label, head, children, minWidth }: { label: string; head: string[]; children: ReactNode; minWidth?: string }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table aria-label={label} className="w-full text-left text-sm" style={{ borderCollapse: "collapse", minWidth }}>
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
  const t = useT();
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
      <Panel title={t("recovery.codes")}>
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
      <Panel title={t("account.profile")} description={`${me.user.email} · ${roleName(t, me.user.role)}`}>
        <form
          className="flex flex-col gap-2.5"
          style={{ maxWidth: 420 }}
          onSubmit={(e) => {
            e.preventDefault();
            void act(() => auth.rename(name.trim()), t("account.nameSaved"));
          }}
        >
          <TextField label={t("common.name")} autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} />
          <div>
            <Button type="submit" size="sm" disabled={!name.trim() || name.trim() === me.user.name}>
              {t("common.save")}
            </Button>
          </div>
        </form>
      </Panel>

      {me.passwordManagedBy && (
        <Panel title={t("account.password")} description={t("account.passwordManaged", { directory: me.passwordManagedBy })}>
          {null}
        </Panel>
      )}
      {me.hasPassword && !me.passwordManagedBy && (
        <Panel title={t("account.password")} description={t("account.passwordSignsOut")}>
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
              }, t("account.passwordChanged"));
            }}
          >
            <TextField label={t("account.currentPassword")} type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
            <PasswordFields password={password} setPassword={setPassword} confirm={confirm} setConfirm={setConfirm} />
            <div>
              <Button type="submit" size="sm" disabled={!current || !passwordOk(password, confirm)}>
                {t("account.changePassword")}
              </Button>
            </div>
          </form>
        </Panel>
      )}

      <Panel title={t("mfa.title")} description={me.user.mfa.totp || me.passkeys.length ? t("account.mfaOn", { count: me.recoveryCodesLeft }) : t("common.off")}>
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="flex items-center gap-2 text-sm">
              <Smartphone className="h-4 w-4" aria-hidden /> {t("account.app")} {me.user.mfa.totp ? <Badge tone="success">{t("common.on")}</Badge> : <Badge>{t("common.off")}</Badge>}
            </span>
            {me.user.mfa.totp ? (
              <Button size="sm" variant="ghost" icon={<Trash2 />} onClick={() => void act(auth.removeTotp, t("account.appRemoved"))}>
                {t("common.remove")}
              </Button>
            ) : (
              !addingTotp && (
                <Button size="sm" icon={<Plus />} onClick={() => setAddingTotp(true)}>
                  {t("common.add")}
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
              <Fingerprint className="h-4 w-4" aria-hidden /> {t("account.passkeys")} {me.passkeys.length ? <Badge tone="success">{me.passkeys.length}</Badge> : <Badge>{t("common.none")}</Badge>}
            </span>
            {passkeysSupported() && (
              <Button
                size="sm"
                icon={<Plus />}
                onClick={() =>
                  void act(async () => {
                    const r = await auth.addPasskey(deviceName(t, navigator.userAgent));
                    if (r.recoveryCodes) setCodes(r.recoveryCodes);
                  }, t("account.passkeyAdded"))
                }
              >
                {t("common.add")}
              </Button>
            )}
          </div>
          {me.passkeys.length > 0 && (
            <Table label={t("account.passkeys")} head={[t("common.name"), t("account.added"), t("common.lastUsed"), ""]}>
              {me.passkeys.map((k) => (
                <tr key={k.id}>
                  <Cell>{k.name}</Cell>
                  <Cell>{when(t, k.createdAt)}</Cell>
                  <Cell>{when(t, k.lastUsedAt)}</Cell>
                  <Cell>
                    <Button size="xs" variant="ghost" icon={<Trash2 />} onClick={() => void act(() => auth.removePasskey(k.id), t("account.passkeyRemoved"))}>
                      {t("common.remove")}
                    </Button>
                  </Cell>
                </tr>
              ))}
            </Table>
          )}
          {(me.user.mfa.totp || me.passkeys.length > 0) && (
            <div>
              <Button size="sm" onClick={() => void act(async () => setCodes(await auth.newRecoveryCodes()))}>
                {t("account.newCodes")}
              </Button>
            </div>
          )}
        </div>
      </Panel>

      <Panel title={t("account.sessions")} description={t("account.sessionsBody")}>
        <Problem error={sessions.error} />
        <Table label={t("account.sessions")} head={[t("account.device"), t("account.address"), t("account.signedIn"), t("account.lastActive"), ""]}>
          {(sessions.rows ?? []).map((s) => (
            <tr key={s.id}>
              <Cell>
                <span title={s.userAgent}>{deviceName(t, s.userAgent)}</span> {s.current && <Badge tone="info">{t("account.thisBrowser")}</Badge>}
              </Cell>
              <Cell mono>{s.ip}</Cell>
              <Cell>{when(t, s.createdAt)}</Cell>
              <Cell>{when(t, s.lastSeenAt)}</Cell>
              <Cell>
                {!s.current && (
                  <Button size="xs" variant="ghost" onClick={() => void act(() => auth.revokeSession(s.id).then(sessions.reload), t("account.sessionSignedOut"))}>
                    {t("common.signOut")}
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

function deviceName(t: T, ua: string) {
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : t("account.browser");
  const os = /Windows/.test(ua) ? "Windows" : /Mac OS X/.test(ua) ? "macOS" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Linux/.test(ua) ? "Linux" : "";
  return os ? t("account.deviceOn", { browser, os }) : browser;
}

function LinkBox({ title, link, expiresAt, onDone }: { title: string; link: string; expiresAt: string; onDone: () => void }) {
  const t = useT();
  return (
    <Callout tone="info" title={title} onDismiss={onDone}>
      <span className="flex flex-col gap-2">
        <span>{t("members.linkOnce", { date: when(t, expiresAt) })}</span>
        <code className="block rounded-md bg-canvas p-2 font-mono text-xs text-fg" style={{ overflowWrap: "anywhere" }}>
          {link}
        </code>
        <span>
          <Button size="xs" icon={<Copy />} onClick={() => copy(link)}>
            {t("members.copyLink")}
          </Button>
        </span>
      </span>
    </Callout>
  );
}

/** Settings → Members: invite, change roles, disable, reset and remove (admins; owners for owners). */
export function MembersSettings() {
  const { me, users } = useAuth();
  const t = useT();
  const members = useList<Member>(auth.members);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [link, setLink] = useState<{ title: string; link: string; expiresAt: string }>();
  const isOwner = me.user.role === "owner";
  const roles = RANK.filter((r) => (r !== "owner" || isOwner) && (r !== "user" || users)).reverse();
  const roleOptions = roles.map((r) => ({ value: r, label: roleName(t, r) }));

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
      <Panel title={t("members.invite")} description={t("members.inviteBody")}>
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void act(async () => {
              const r = await auth.invite({ email, name: name || undefined, role });
              setLink({ title: t("members.invitationFor", { email: r.member.email }), link: r.link, expiresAt: r.linkExpiresAt });
              setEmail("");
              setName("");
            });
          }}
        >
          <TextField label={t("common.email")} type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          <TextField label={t("common.name")} value={name} onChange={(e) => setName(e.target.value)} />
          <SelectField label={t("common.role")} value={role} onChange={(e) => setRole(e.target.value as Role)} options={roleOptions} />
          <Button type="submit" variant="primary" icon={<Plus />} disabled={!email.includes("@")}>
            {t("members.invite")}
          </Button>
        </form>
      </Panel>
      {link && <LinkBox {...link} onDone={() => setLink(undefined)} />}
      <Problem error={members.error} />
      <Panel title={t("members.title")} flush>
        <Table label={t("members.title")} head={[t("common.name"), t("common.email"), t("common.role"), t("common.status"), t("members.secondFactor"), t("members.lastSignIn"), ""]}>
          {(members.rows ?? []).map((m) => {
            const manageable = m.id !== me.user.id && (isOwner || m.role !== "owner");
            return (
              <tr key={m.id}>
                <Cell>{m.name}</Cell>
                <Cell mono>{m.email}</Cell>
                <Cell>
                  {manageable ? (
                    <SelectField aria-label={t("members.roleOf", { email: m.email })} value={m.role} onChange={(e) => void act(() => auth.updateMember(m.id, { role: e.target.value as Role }))} options={roleOptions} />
                  ) : (
                    roleName(t, m.role)
                  )}
                </Cell>
                <Cell>
                  <Badge tone={m.status === "active" ? "success" : m.status === "invited" ? "info" : "neutral"}>{t(`members.status.${m.status}`)}</Badge>
                </Cell>
                <Cell>{m.providers.length ? m.providers.join(", ") : m.mfa.totp || m.mfa.passkeys ? t("common.on") : t("common.off")}</Cell>
                <Cell>{when(t, m.lastSignInAt)}</Cell>
                <Cell>
                  {manageable && (
                    <span className="flex gap-1">
                      <Button
                        size="xs"
                        variant="ghost"
                        onClick={() =>
                          void act(async () => {
                            const r = await auth.resetMember(m.id, { mfa: confirm(t("members.alsoMfa", { email: m.email })) });
                            // Someone whose password another directory keeps gets no link: they sign in with it again.
                            if (r.link && r.linkExpiresAt) setLink({ title: t("members.passwordLinkFor", { email: m.email }), link: r.link, expiresAt: r.linkExpiresAt });
                          })
                        }
                      >
                        {m.status === "invited" ? t("members.newLink") : t("members.reset")}
                      </Button>
                      {m.status !== "invited" && (
                        <Button size="xs" variant="ghost" onClick={() => void act(() => auth.updateMember(m.id, { status: m.status === "active" ? "disabled" : "active" }))}>
                          {m.status === "active" ? t("members.disable") : t("members.enable")}
                        </Button>
                      )}
                      <Button size="xs" variant="ghost" icon={<Trash2 />} onClick={() => confirm(t("members.confirmRemove", { email: m.email })) && void act(() => auth.removeMember(m.id))}>
                        {t("common.remove")}
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
  const t = useT();
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
      <Panel title={t("tokens.new")} description={t("tokens.newBody")}>
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
          <TextField label={t("common.name")} value={name} onChange={(e) => setName(e.target.value)} placeholder={t("tokens.placeholder")} />
          <SelectField label={t("common.role")} value={role} onChange={(e) => setRole(e.target.value as ApiToken["role"])} options={roles.map((r) => ({ value: r, label: roleName(t, r) }))} />
          <SelectField
            label={t("tokens.expires")}
            value={days}
            onChange={(e) => setDays(e.target.value)}
            options={[
              { value: "7", label: t("tokens.in7") },
              { value: "30", label: t("tokens.in30") },
              { value: "90", label: t("tokens.in90") },
              { value: "366", label: t("tokens.inYear") },
            ]}
          />
          <Button type="submit" variant="primary" icon={<Plus />} disabled={!name.trim()}>
            {t("common.create")}
          </Button>
        </form>
      </Panel>
      {created && (
        <Callout tone="warning" title={t("tokens.copyNow", { name: created.name })} onDismiss={() => setCreated(undefined)}>
          <span className="flex flex-col gap-2">
            <span>{t("tokens.notShownAgain")}</span>
            <code className="block rounded-md bg-canvas p-2 font-mono text-xs text-fg" style={{ overflowWrap: "anywhere" }}>
              {created.token}
            </code>
            <span>
              <Button size="xs" icon={<Copy />} onClick={() => copy(created.token)}>
                {t("tokens.copy")}
              </Button>
            </span>
          </span>
        </Callout>
      )}
      <Problem error={tokens.error} />
      <Panel title={t("tokens.title")} flush>
        <Table label={t("tokens.label")} head={[t("common.name"), t("common.role"), t("tokens.createdBy"), t("tokens.expires"), t("common.lastUsed"), ""]}>
          {(tokens.rows ?? []).map((tk) => (
            <tr key={tk.id}>
              <Cell>{tk.name}</Cell>
              <Cell>{roleName(t, tk.role)}</Cell>
              <Cell mono>{tk.createdBy ?? t("tokens.removedMember")}</Cell>
              <Cell>{tk.expired ? <Badge tone="danger">{t("tokens.expired")}</Badge> : when(t, tk.expiresAt)}</Cell>
              <Cell>{when(t, tk.lastUsedAt)}</Cell>
              <Cell>
                <Button size="xs" variant="ghost" icon={<Trash2 />} onClick={() => confirm(t("tokens.confirmRevoke", { name: tk.name })) && void act(() => auth.revokeToken(tk.id))}>
                  {t("tokens.revoke")}
                </Button>
              </Cell>
            </tr>
          ))}
        </Table>
      </Panel>
    </div>
  );
}

// ---- Sign-in ------------------------------------------------------------------------------------------------------

const fieldClass = "w-full rounded-md border border-line-strong bg-surface px-2.5 py-1.5 font-mono text-sm text-fg placeholder:text-fg-subtle";

/** "group = role" per line, as people write it, to the role mapping the API takes. */
function parseMapping(t: T, text: string): Record<string, Role> {
  const out: Record<string, Role> = {};
  for (const line of text.split("\n").map((l) => l.trim()).filter(Boolean)) {
    const i = line.lastIndexOf("=");
    const group = line.slice(0, i).trim();
    const role = line.slice(i + 1).trim().toLowerCase();
    if (i < 1 || !group || !(RANK as string[]).includes(role)) throw new Error(t("providers.badMapping", { line }));
    out[group] = role as Role;
  }
  return out;
}

const mappingText = (m: Record<string, Role>) =>
  Object.entries(m)
    .map(([g, r]) => `${g} = ${r}`)
    .join("\n");

function ProviderForm({ editing, template, onSaved, onCancel }: { editing?: Provider; template: string; onSaved: () => void; onCancel: () => void }) {
  const { users } = useAuth();
  const t = useT();
  // Owners are made by owners, not by whoever a provider sends.
  const joinRoles: Role[] = [...(users ? (["user"] as const) : []), "viewer", "editor", "admin"];
  const [presetId, setPresetId] = useState(editing?.preset ?? "keycloak");
  const p = PRESETS.find((x) => x.id === presetId) ?? PRESETS[PRESETS.length - 1]!;
  const [id, setId] = useState(editing?.id ?? "");
  const [name, setName] = useState(editing?.name ?? "");
  const [issuer, setIssuer] = useState(editing?.issuer ?? "");
  const [clientId, setClientId] = useState(editing?.clientId ?? "");
  const [clientSecret, setClientSecret] = useState("");
  const [groupsClaim, setGroupsClaim] = useState(editing ? (editing.groupsClaim ?? "") : (p.groupsClaim ?? ""));
  const [mapping, setMapping] = useState(editing ? mappingText(editing.roleMapping) : "");
  const [defaultRole, setDefaultRole] = useState<Role | "">(editing?.defaultRole ?? "");
  const [domains, setDomains] = useState(editing?.allowedDomains.join(", ") ?? "");
  const [enabled, setEnabled] = useState(editing?.enabled ?? true);
  const [autoRedirect, setAutoRedirect] = useState(editing?.autoRedirect ?? false);
  const [check, setCheck] = useState<{ ok: boolean; text: string }>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const redirectUri = editing?.redirectUri ?? template.replace("{id}", id || p.id);

  const choose = (next: string) => {
    const n = PRESETS.find((x) => x.id === next)!;
    setPresetId(next);
    setGroupsClaim(n.groupsClaim ?? "");
    setCheck(undefined);
  };
  const discover = async () => {
    setCheck(undefined);
    try {
      const d = await auth.discoverProvider(issuer.trim());
      setCheck(d.pkce ? { ok: true, text: t("providers.answers", { issuer: d.issuer }) } : { ok: false, text: t("providers.noPkce", { issuer: d.issuer }) });
    } catch (err) {
      setCheck({ ok: false, text: message(err) });
    }
  };
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setError(undefined);
    setBusy(true);
    try {
      const body: ProviderChange = {
        name: name.trim() || p.name,
        issuer: issuer.trim(),
        clientId: clientId.trim(),
        groupsClaim: groupsClaim.trim() || null,
        roleMapping: parseMapping(t, mapping),
        defaultRole: defaultRole || null,
        allowedDomains: domains
          .split(",")
          .map((d) => d.trim())
          .filter(Boolean),
        enabled,
        autoRedirect,
        ...(clientSecret && { clientSecret }),
      };
      if (editing) await auth.updateProvider(editing.id, body);
      else await auth.addProvider({ ...body, preset: presetId, ...(id.trim() && { id: id.trim() }) });
      onSaved();
    } catch (err) {
      setError(message(err));
      setBusy(false);
    }
  };

  return (
    <Panel title={editing ? t("providers.changeOne", { name: editing.name }) : t("providers.addTitle")} description={t("providers.addBody")}>
      <form className="flex flex-col gap-4" onSubmit={save}>
        {!editing && (
          <SelectField label={t("providers.provider")} value={presetId} onChange={(e) => choose(e.target.value)} options={PRESETS.map((x) => ({ value: x.id, label: x.id === "generic" ? t("providers.generic") : x.name }))} />
        )}
        <div className="flex flex-col gap-2 rounded-md bg-canvas p-3 text-sm">
          <span className="font-medium text-fg">{t("providers.at", { provider: p.id === "generic" ? t("providers.yourProvider") : p.name })}</span>
          <ol className="m-0 flex list-decimal flex-col gap-1 pl-5 text-fg-muted">
            {p.steps.map((s) => (
              <li key={s}>{s.replace("{redirectUri}", redirectUri)}</li>
            ))}
          </ol>
          <span className="flex flex-wrap items-center gap-2">
            <code className="rounded bg-surface px-1.5 py-0.5 font-mono text-xs text-fg" style={{ overflowWrap: "anywhere" }}>
              {redirectUri}
            </code>
            <Button size="xs" type="button" icon={<Copy />} onClick={() => copy(redirectUri)}>
              {t("providers.copyRedirect")}
            </Button>
            <a href={p.docs} target="_blank" rel="noreferrer" className="text-xs">
              {t("providers.docs", { provider: p.name })}
            </a>
          </span>
          {p.notes?.map((n) => (
            <span key={n} className="text-xs text-fg-muted">
              {n}
            </span>
          ))}
        </div>
        <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(16rem, 1fr))" }}>
          <TextField label={t("providers.buttonName")} placeholder={p.name} value={name} onChange={(e) => setName(e.target.value)} />
          {!editing && <TextField label="Id" mono placeholder={p.id} hint={t("providers.idHint")} value={id} onChange={(e) => setId(e.target.value.toLowerCase())} />}
          <TextField
            label={t("providers.issuer")}
            mono
            placeholder={p.issuerExample}
            value={issuer}
            onChange={(e) => (setIssuer(e.target.value), setCheck(undefined))}
            error={check && !check.ok ? check.text : undefined}
            hint={check?.ok ? check.text : t("providers.issuerHint", { example: p.issuerExample })}
            adornment={
              <Button size="xs" type="button" variant="ghost" disabled={!issuer.trim()} onClick={() => void discover()}>
                {t("providers.check")}
              </Button>
            }
          />
          <TextField label="Client ID" mono value={clientId} onChange={(e) => setClientId(e.target.value)} />
          <TextField
            label={t("providers.clientSecret")}
            type="password"
            autoComplete="off"
            value={clientSecret}
            placeholder={editing?.hasClientSecret ? t("providers.keepSecret") : ""}
            hint={t("providers.secretHint")}
            onChange={(e) => setClientSecret(e.target.value)}
          />
          <TextField label={t("providers.groupsClaim")} mono placeholder="groups" hint={t("providers.groupsHint")} value={groupsClaim} onChange={(e) => setGroupsClaim(e.target.value)} />
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="oa-role-mapping" className="text-xs font-medium text-fg">
            {t("providers.rolesFromGroups")}
          </label>
          <textarea id="oa-role-mapping" rows={3} className={fieldClass} placeholder={"ops-admins = admin\nstaff = viewer"} value={mapping} onChange={(e) => setMapping(e.target.value)} />
          <span className="text-xs text-fg-muted">{t("providers.mappingHint")}</span>
        </div>
        <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(16rem, 1fr))" }}>
          <SelectField
            label={t("providers.uninvited")}
            value={defaultRole}
            onChange={(e) => setDefaultRole(e.target.value as Role | "")}
            options={[{ value: "", label: t("providers.refused") }, ...joinRoles.map((r) => ({ value: r, label: t("providers.joinAs", { role: roleName(t, r) }) }))]}
          />
          <TextField label={t("providers.domains")} placeholder="example.com" hint={t("providers.domainsHint")} value={domains} onChange={(e) => setDomains(e.target.value)} />
        </div>
        <Switch checked={enabled} onCheckedChange={setEnabled} label={t("providers.show")} description={t("providers.showHint")} />
        <Switch
          checked={autoRedirect}
          onCheckedChange={setAutoRedirect}
          label={t("providers.straight")}
          description={t("providers.straightHint")}
        />
        <Problem error={error} title={t("common.notSaved")} />
        <span className="flex gap-2">
          <Button type="submit" variant="primary" loading={busy} disabled={!issuer.trim() || !clientId.trim()}>
            {editing ? t("common.save") : t("providers.addProvider")}
          </Button>
          <Button type="button" variant="ghost" onClick={onCancel}>
            {t("common.cancel")}
          </Button>
        </span>
      </form>
    </Panel>
  );
}

/** Settings → Sign-in: identity providers (ADR 0033). Admins see them; owners add, change and remove them. */
export function SignInSettings() {
  const { me } = useAuth();
  const t = useT();
  const isOwner = me.user.role === "owner";
  const [data, setData] = useState<{ providers: Provider[]; redirectUriTemplate: string }>();
  const [error, setError] = useState<string>();
  const [form, setForm] = useState<{ editing?: Provider }>();
  const reload = useCallback(() => auth.providers().then(setData, (err: unknown) => setError(message(err))), []);
  useEffect(() => {
    void reload();
  }, [reload]);

  const remove = async (p: Provider) => {
    if (!confirm(t("providers.confirmRemove", { name: p.name }))) return;
    try {
      await auth.removeProvider(p.id);
      await reload();
    } catch (err) {
      setError(message(err));
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {!isOwner && (
        <Callout tone="info" title={t("providers.ownersOnly")}>
          {t("providers.ownersOnlyBody")}
        </Callout>
      )}
      <Problem error={error} />
      {form && data ? (
        <ProviderForm editing={form.editing} template={data.redirectUriTemplate} onSaved={() => (setForm(undefined), void reload())} onCancel={() => setForm(undefined)} />
      ) : (
        isOwner && (
          <span>
            <Button variant="primary" icon={<Plus />} onClick={() => setForm({})}>
              {t("providers.addA")}
            </Button>
          </span>
        )
      )}
      <Panel title={t("providers.title")} description={t("providers.titleBody")} flush>
        {data?.providers.length === 0 ? (
          <p className="m-0 px-3 pb-3 text-sm text-fg-muted">{t("providers.noneYet")}</p>
        ) : (
          <Table label={t("providers.title")} head={[t("common.name"), t("providers.issuer"), t("providers.rolesFromGroups"), t("common.status"), ""]} minWidth="52rem">
            {(data?.providers ?? []).map((p) => (
              <tr key={p.id}>
                <Cell>{p.name}</Cell>
                <Cell mono>{p.issuer}</Cell>
                <Cell>
                  {Object.keys(p.roleMapping).length
                    ? Object.entries(p.roleMapping)
                        .map(([g, r]) => `${g} → ${roleName(t, r)}`)
                        .join(", ")
                    : p.defaultRole
                      ? t("providers.everyoneJoins", { role: roleName(t, p.defaultRole) })
                      : t("providers.invitedOnly")}
                </Cell>
                <Cell>
                  <span className="flex gap-1 whitespace-nowrap">
                    {p.source === "environment" ? <Badge tone="neutral">{t("providers.environment")}</Badge> : <Badge tone={p.enabled ? "success" : "neutral"}>{p.enabled ? t("common.on") : t("common.off")}</Badge>}
                    {p.autoRedirect && <Badge tone="neutral">{t("providers.straightBadge")}</Badge>}
                  </span>
                </Cell>
                <Cell>
                  {isOwner && p.source === "settings" && (
                    <span className="flex gap-1 whitespace-nowrap">
                      <Button size="xs" variant="ghost" icon={<Pencil />} onClick={() => setForm({ editing: p })}>
                        {t("common.change")}
                      </Button>
                      <Button size="xs" variant="ghost" icon={<Trash2 />} onClick={() => void remove(p)}>
                        {t("common.remove")}
                      </Button>
                    </span>
                  )}
                </Cell>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </div>
  );
}
