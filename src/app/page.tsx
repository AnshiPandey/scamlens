
"use client";

import { useState } from "react";

export default function Home() {
  const [message, setMessage] = useState("");
  const [analysis, setAnalysis] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function analyzeMessage() {
    if (!message.trim()) {
      setError("Please paste a message to investigate.");
      return;
    }

    setLoading(true);
    setError("");
    setAnalysis("");

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Analysis failed.");
      }

      setAnalysis(data.analysis);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Something went wrong."
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="min-h-screen bg-slate-950 px-5 py-12 text-white">
      <div className="mx-auto max-w-3xl">
        <header className="mb-10">
          <p className="mb-3 text-sm font-semibold uppercase tracking-[0.25em] text-cyan-400">
            AI-powered scam investigation
          </p>
          <h1 className="text-5xl font-bold tracking-tight">
            Scam<span className="text-cyan-400">Lens</span>
          </h1>
          <p className="mt-4 max-w-xl leading-7 text-slate-300">
            Investigate suspicious messages, understand warning signs,
            and discover safer next steps with evidence-based analysis.
          </p>
        </header>

        <section className="rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
          <label
            htmlFor="message"
            className="mb-3 block font-medium text-slate-100"
          >
            Suspicious message
          </label>

          <textarea
            id="message"
            value={message}
            onChange={(event) => setMessage(event.target.value)}
            placeholder="Paste a suspicious SMS, email, or message here..."
            maxLength={5000}
            rows={6}
            className="w-full resize-y rounded-xl border border-slate-700 bg-slate-950 p-4 text-sm leading-6 outline-none placeholder:text-slate-500 focus:border-cyan-400"
          />

          <div className="mt-3 flex items-center justify-between gap-4">
            <span className="text-xs text-slate-400">
              {message.length}/5000 characters
            </span>

            <button
              onClick={analyzeMessage}
              disabled={loading || !message.trim()}
              className="rounded-xl bg-cyan-400 px-5 py-3 font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? "Investigating..." : "Analyze message"}
            </button>
          </div>

          {error && (
            <p role="alert" className="mt-4 text-sm text-red-400">
              {error}
            </p>
          )}
        </section>

        {analysis && (
          <section className="mt-6 rounded-2xl border border-slate-700 bg-slate-900 p-6">
            <h2 className="text-xl font-semibold text-cyan-400">
              Investigation results
            </h2>
            <p className="mt-4 whitespace-pre-wrap leading-7 text-slate-200">
              {analysis}
            </p>
            <p className="mt-5 border-t border-slate-700 pt-4 text-sm text-slate-400">
              AI analysis can be incorrect. Independently verify claims
              and never share passwords, PINs, or OTPs with untrusted sources.
            </p>
          </section>
        )}

        <footer className="mt-10 text-center text-xs text-slate-500">
          ScamLens · Evidence first, safer decisions
        </footer>
      </div>
    </main>
  );
}
