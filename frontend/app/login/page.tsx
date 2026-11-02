"use client";

import { FormEvent, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { login } from "@/lib/api";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await login(username, password);
      window.location.assign("/dashboard");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Authentication failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-[#070a0d] p-6">
      <form onSubmit={submit} className="dashboard-panel w-full max-w-md rounded-2xl p-8">
        <div className="mb-8 flex items-center gap-3">
          <ShieldCheck className="text-[#00ff41]" />
          <div>
            <p className="font-mono text-sm font-bold tracking-[0.25em] text-[#c9d1d9]">RAJAWALI</p>
            <p className="font-mono text-[10px] uppercase tracking-widest text-[#82909b]">Secure operations access</p>
          </div>
        </div>
        <label className="mb-4 block font-mono text-xs text-[#82909b]">Username
          <input required value={username} onChange={(event) => setUsername(event.target.value)} className="mt-2 w-full rounded border border-[#1c2a32] bg-[#080d11] p-3 text-sm text-white outline-none focus:border-[#00ff41]" autoComplete="username" />
        </label>
        <label className="mb-5 block font-mono text-xs text-[#82909b]">Password
          <input required type="password" value={password} onChange={(event) => setPassword(event.target.value)} className="mt-2 w-full rounded border border-[#1c2a32] bg-[#080d11] p-3 text-sm text-white outline-none focus:border-[#00ff41]" autoComplete="current-password" />
        </label>
        {error && <p role="alert" className="mb-4 rounded border border-[#ff6b35]/40 bg-[#ff6b35]/10 p-3 text-xs text-[#ff8c62]">{error}</p>}
        <button disabled={loading} className="w-full rounded bg-[#00ff41] px-4 py-3 font-mono text-xs font-bold uppercase tracking-widest text-[#061008] disabled:opacity-50">{loading ? "Authenticating..." : "Sign in"}</button>
      </form>
    </main>
  );
}
