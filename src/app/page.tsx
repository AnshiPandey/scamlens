"use client";

import { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

type ToolResult = {
  content?: Array<{ type?: string; text?: string }>;
  structuredContent?: unknown;
  isError?: boolean;
};

type URLCheck = {
  url: string;
  result?: ToolResult;
  error?: string;
};

type MCPFindings = {
  toolsCalled?: string[];
  unavailable?: boolean;
  error?: string;
  extraction?: ToolResult;
  messageCheck?: ToolResult;
  urlChecks?: URLCheck[];
};

type AnalysisResponse = {
  analysis?: string;
  aiStatus?: "available" | "temporarily_unavailable";
  mcpFindings?: MCPFindings;
  error?: string;
};

const EXAMPLE_MESSAGE =
  "URGENT! Your bank account will be blocked. Verify your password immediately: https://example.com/login";

function formatResult(value: unknown): string {
  if (value === undefined || value === null) {
    return "No result returned.";
  }

  if (typeof value === "object" && "content" in value) {
    const result = value as ToolResult;

    if (result.content?.length) {
      return result.content
        .map((item) => item.text ?? JSON.stringify(item))
        .join("\n\n");
    }

    if (result.structuredContent !== undefined) {
      return JSON.stringify(result.structuredContent, null, 2);
    }
  }

  return typeof value === "string"
    ? value
    : JSON.stringify(value, null, 2);
}

function parseToolData(value: unknown): Record<string, unknown> | null {
  const raw = formatResult(value);

  try {
    const parsed: unknown = JSON.parse(raw);

    if (
      parsed !== null &&
      typeof parsed === "object" &&
      !Array.isArray(parsed)
    ) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // Keep the original result available in the expandable panel.
  }
  
  return null;
}

function ResultCard({
  title,
  description,
  result,
}: {
  title: string;
  description: string;
  result: unknown;
}) {
  return (
    <details className="group rounded-xl border border-slate-700 bg-slate-950/60">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 p-4">
        <div>
          <h3 className="font-semibold text-slate-100">{title}</h3>
          <p className="mt-1 text-sm text-slate-400">{description}</p>
        </div>
        <span className="text-cyan-400 transition group-open:rotate-180">
          ▼
        </span>
      </summary>
      <div className="border-t border-slate-800 p-4">
        <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words text-xs leading-6 text-slate-300">
          {formatResult(result)}
        </pre>
      </div>
    </details>
  );
}

function EvidenceSummary({ findings }: { findings: MCPFindings }) {
  const extraction = parseToolData(findings.extraction);
  const messageCheck = parseToolData(findings.messageCheck);

  const getStrings = (value: unknown): string[] =>
    Array.isArray(value)
      ? value.filter((item): item is string => typeof item === "string")
      : [];

  const urls = getStrings(extraction?.urls);
  const phoneNumbers = getStrings(extraction?.phoneNumbers);
  const indicators = getStrings(extraction?.indicators);
  const assessment =
    typeof messageCheck?.assessment === "string"
      ? messageCheck.assessment
      : null;

  const urlFindings = (findings.urlChecks ?? []).flatMap((check) => {
    const data = parseToolData(check.result);

    return getStrings(data?.findings).map(
      (finding) => `${check.url}: ${finding}`
    );
  });

  // Add transparent, local-only context for URLs already extracted by MCP.
  // These checks do not contact the destination or verify its reputation.
  const localUrlContext = urls.flatMap((url) => {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();
      const findingsForUrl: string[] = [];

      if (parsed.protocol === "http:") {
        findingsForUrl.push(`${url}: Uses HTTP rather than HTTPS; the connection is not encrypted in transit.`);
      }

      if (
        hostname === "example.com" ||
        hostname.endsWith(".example.com") ||
        hostname === "example.org" ||
        hostname.endsWith(".example.org") ||
        hostname === "example.net" ||
        hostname.endsWith(".example.net")
      ) {
        findingsForUrl.push(`${url}: Uses a reserved example domain commonly used in documentation and testing; this does not establish that a real phishing site exists.`);
      }

      if (/sbi|kyc|verify|verification|bank|account/i.test(hostname)) {
        findingsForUrl.push(`${url}: Hostname contains banking or verification-related keywords. This is only a structural heuristic and does not prove impersonation.`);
      }

      return findingsForUrl;
    } catch {
      return [];
    }
  });

  const reputationNotChecked = (findings.urlChecks ?? []).some((check) => {
    const data = parseToolData(check.result);
    return data?.reputationStatus === "not_checked";
  });

  const networkNotUsed = (findings.urlChecks ?? []).some((check) => {
    const data = parseToolData(check.result);
    return data?.networkRequestMade === false;
  });

  const recommendedActions: string[] = [];

  const allIndicators = indicators.join(" ").toLowerCase();

  if (
    allIndicators.includes("account verification") ||
    allIndicators.includes("authentication") ||
    allIndicators.includes("password")
  ) {
    recommendedActions.push(
      "Do not use the message's link to sign in. Open the official app or type the organization's known website address yourself."
    );
  }

  if (
    allIndicators.includes("prize") ||
    allIndicators.includes("reward")
  ) {
    recommendedActions.push(
      "Verify any prize through the organization's official website. Do not pay a fee or share sensitive information to claim it."
    );
  }

  if (
    allIndicators.includes("payment") ||
    allIndicators.includes("money-transfer")
  ) {
    recommendedActions.push(
      "Pause before sending money or buying gift cards. Independently verify the request using a trusted contact method."
    );
  }

  if (urls.length > 0) {
    recommendedActions.push(
      "Avoid opening suspicious links. ScamLens has not checked the URLs against an external reputation service."
    );
  }

  if (allIndicators.includes("urgency")) {
    recommendedActions.push(
      "Do not let urgent deadlines pressure you into acting before you verify the claim."
    );
  }

  if (recommendedActions.length === 0) {
    recommendedActions.push(
      "Verify unexpected claims through an official website, app, or independently obtained contact details."
    );
  }

    const sections = [
    {
      title: "Observed facts",
      description: "Items extracted directly from the submitted message.",
      items: [
        ...urls.map((url) => `URL found: ${url}`),
        ...phoneNumbers.map((phone) => `Phone number found: ${phone}`),
      ],
      empty: "No URLs or phone numbers were extracted.",
      color: "border-sky-500/30 bg-sky-500/5",
      headingColor: "text-sky-300",
    },
    {
      title: "Warning signs",
      description: "Heuristic signals that deserve closer review.",
      items: [...new Set([...indicators, ...urlFindings, ...localUrlContext])],
      empty: "No warning signs were returned by the available checks.",
      color: "border-amber-500/30 bg-amber-500/5",
      headingColor: "text-amber-300",
    },
    {
      title: "Unknowns and limitations",
      description: "What these checks have not established.",
      items: [
        ...(reputationNotChecked
          ? ["External URL reputation has not been checked."]
          : []),
        ...(networkNotUsed
          ? ["The destination website was not opened; no network request was made."]
          : []),
        "Hostname keyword checks are structural heuristics, not proof of impersonation.",
        "These heuristic findings do not prove that a message is fraudulent or safe.",
      ],
      empty: "Review the individual tool results for additional limitations.",
      color: "border-violet-500/30 bg-violet-500/5",
      headingColor: "text-violet-300",
    },
    {
      title: "Recommended actions",
      description: "Practical next steps based on extracted warning signs.",
      items: recommendedActions,
      empty: "Verify important claims independently.",
      color: "border-emerald-500/30 bg-emerald-500/5",
      headingColor: "text-emerald-300",
    },
  ];

  return (
    <div className="mt-6">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-lg font-semibold text-white">
            Evidence summary
          </h3>
          <p className="mt-1 text-sm text-slate-400">
            Separate extracted facts from heuristic signals and unknowns.
          </p>
        </div>

        {assessment && (
          <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs font-semibold text-amber-300">
            Heuristic assessment: {assessment.replaceAll("_", " ")}
          </span>
        )}
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        {sections.map((section) => (
          <section
  key={section.title}
  className={`rounded-xl border p-4 ${
    section.title === "Recommended actions" ? "md:col-span-3" : ""
  } ${section.color}`}
>
            <h4 className={`font-semibold ${section.headingColor}`}>
              {section.title}
            </h4>

            <p className="mt-2 text-xs leading-5 text-slate-400">
              {section.description}
            </p>

            {section.items.length > 0 ? (
              <ul className="mt-4 space-y-3">
                {section.items.map((item, index) => (
                  <li
                    key={`${item}-${index}`}
                    className="break-words text-sm leading-6 text-slate-200"
                  >
                    <span className="mr-2 text-slate-500">•</span>
                    {item}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-4 text-sm leading-6 text-slate-400">
                {section.empty}
              </p>
            )}
          </section>
        ))}
      </div>
    </div>
  );
}

export default function Home() {
  const [message, setMessage] = useState("");
  const [analysis, setAnalysis] = useState("");
  const [mcpFindings, setMcpFindings] =
    useState<MCPFindings | null>(null);
  const [aiStatus, setAiStatus] = useState<
    "available" | "temporarily_unavailable" | null
  >(null);
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
    setMcpFindings(null);
    setAiStatus(null);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: message.trim() }),
      });

      const data: AnalysisResponse = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Investigation failed.");
      }

      setAnalysis(data.analysis ?? "No analysis was returned.");
      setMcpFindings(data.mcpFindings ?? null);
      setAiStatus(data.aiStatus ?? null);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Something went wrong. Please try again."
      );
    } finally {
      setLoading(false);
    }
  }

  function resetInvestigation() {
    setMessage("");
    setAnalysis("");
    setMcpFindings(null);
    setAiStatus(null);
    setError("");
  }

  const toolsCalled = mcpFindings?.toolsCalled ?? [];

  return (
    <main className="min-h-screen bg-[#080d18] px-4 py-8 text-white sm:px-6 lg:px-8">
      <div className="mx-auto max-w-6xl">
        <header className="mb-10 flex flex-col justify-between gap-5 sm:flex-row sm:items-center">
          <div>
            <div className="mb-3 flex items-center gap-2">
              <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-cyan-400/10 text-xl text-cyan-300">
                ◈
              </span>
              <span className="text-lg font-bold tracking-tight">
                Scam<span className="text-cyan-400">Lens</span>
              </span>
            </div>

            <p className="text-sm font-medium uppercase tracking-[0.2em] text-cyan-400">
              AI-powered scam investigation
            </p>

            <h1 className="mt-3 max-w-2xl text-3xl font-bold tracking-tight sm:text-5xl">
              Look closer.
              <span className="block text-slate-400">
                Stay one step ahead.
              </span>
            </h1>

            <p className="mt-4 max-w-2xl leading-7 text-slate-400">
              Investigate suspicious messages and links. Understand the
              warning signs, see the evidence, and choose safer next steps.
            </p>
          </div>

          <div className="flex w-fit items-center gap-2 rounded-full border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-300">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
            MCP investigation enabled
          </div>
        </header>

        <section className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 shadow-xl sm:p-7">
            <div className="mb-6">
              <p className="text-sm font-medium text-cyan-400">
                STEP 01
              </p>
              <h2 className="mt-2 text-xl font-semibold">
                Submit a suspicious message
              </h2>
              <p className="mt-2 text-sm leading-6 text-slate-400">
                Paste an SMS, email, or message. Include its URL if you
                want ScamLens to inspect the link structure.
              </p>
            </div>

            <label
              htmlFor="message"
              className="mb-2 block text-sm font-medium text-slate-200"
            >
              Message to investigate
            </label>

            <textarea
              id="message"
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              placeholder="Paste the suspicious message here..."
              maxLength={5000}
              rows={8}
              disabled={loading}
              className="w-full resize-y rounded-xl border border-slate-700 bg-[#080d18] p-4 text-sm leading-6 text-white outline-none placeholder:text-slate-600 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/10 disabled:opacity-60"
            />

            <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
              <span>Keep passwords and OTPs out of test messages.</span>
              <span>{message.length}/5000</span>
            </div>

            <div className="mt-5 flex flex-wrap gap-3">
              <button
                onClick={analyzeMessage}
                disabled={loading || !message.trim()}
                className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-cyan-400 px-5 py-3.5 font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50 sm:flex-none"
              >
                {loading ? (
                  <>
                    <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950/30 border-t-slate-950" />
                    Investigating...
                  </>
                ) : (
                  <>Investigate message ↗</>
                )}
              </button>

              <button
                onClick={resetInvestigation}
                disabled={loading}
                className="rounded-xl border border-slate-700 px-5 py-3.5 text-sm font-medium text-slate-300 transition hover:bg-slate-800 disabled:opacity-50"
              >
                Reset
              </button>
            </div>

            <button
              onClick={() => {
                setMessage(EXAMPLE_MESSAGE);
                setError("");
              }}
              disabled={loading}
              className="mt-4 text-sm text-cyan-300 underline decoration-cyan-300/30 underline-offset-4 hover:text-cyan-200"
            >
              Try an example suspicious message
            </button>

            {error && (
              <div
                role="alert"
                className="mt-5 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm leading-6 text-red-300"
              >
                {error}
              </div>
            )}
          </div>

          <aside className="rounded-2xl border border-slate-800 bg-slate-900/50 p-5 sm:p-7">
            <p className="text-sm font-medium text-cyan-400">
              HOW IT WORKS
            </p>
            <h2 className="mt-2 text-xl font-semibold">
              Evidence before conclusions
            </h2>
            <p className="mt-2 text-sm leading-6 text-slate-400">
              ScamLens combines deterministic MCP checks with an AI
              explanation to help you understand a suspicious message.
            </p>

            <div className="mt-7 space-y-5">
              {[
                {
                  number: "01",
                  title: "Extract indicators",
                  detail:
                    "Identify links, urgency, credential requests, and other warning signs.",
                },
                {
                  number: "02",
                  title: "Inspect the message",
                  detail:
                    "Apply heuristic checks to help assess suspicious patterns.",
                },
                {
                  number: "03",
                  title: "Inspect URL structure",
                  detail:
                    "Check available structural signals without visiting the destination.",
                },
                {
                  number: "04",
                  title: "Explain the findings",
                  detail:
                    "Use Gemini to summarize evidence, unknowns, and safer next steps.",
                },
              ].map((step) => (
                <div key={step.number} className="flex gap-4">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-slate-700 bg-slate-800 text-sm font-semibold text-cyan-300">
                    {step.number}
                  </div>
                  <div>
                    <h3 className="font-medium text-slate-200">
                      {step.title}
                    </h3>
                    <p className="mt-1 text-sm leading-6 text-slate-400">
                      {step.detail}
                    </p>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-7 rounded-xl border border-amber-400/20 bg-amber-400/5 p-4">
              <p className="text-sm font-semibold text-amber-300">
                Important limitation
              </p>
              <p className="mt-2 text-sm leading-6 text-slate-400">
                Structural URL inspection is not an external reputation
                check. A missing warning does not prove a message or link
                is safe.
              </p>
            </div>
          </aside>
        </section>
       {(analysis || mcpFindings) && (
          <section
            aria-live="polite"
            className="mt-8 space-y-6"
          >
            <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 sm:p-7">
              <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
                <div>
                  <p className="text-sm font-medium text-cyan-400">
                    INVESTIGATION REPORT
                  </p>
                  <h2 className="mt-2 text-2xl font-bold">
                    Your results
                  </h2>
                  <p className="mt-2 text-sm text-slate-400">
                    Review the findings and verify important claims
                    independently.
                  </p>
                </div>

                {aiStatus && (
                  <span
                    className={`w-fit rounded-full border px-3 py-1.5 text-xs font-medium ${
                      aiStatus === "available"
                        ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                        : "border-amber-500/30 bg-amber-500/10 text-amber-300"
                    }`}
                  >
                    {aiStatus === "available"
                      ? "AI explanation available"
                      : "AI temporarily unavailable"}
                  </span>
                )}
              </div>

              {analysis && (
  <div className="prose prose-invert mt-6 max-w-none break-words prose-headings:font-semibold prose-headings:text-white prose-p:leading-7 prose-p:text-slate-200 prose-strong:text-white prose-li:text-slate-200 prose-a:text-cyan-300 prose-a:underline prose-code:rounded prose-code:bg-slate-800 prose-code:px-1 prose-code:text-cyan-200 prose-pre:overflow-x-auto prose-pre:rounded-xl prose-pre:bg-slate-950 prose-hr:border-slate-700">
    <ReactMarkdown remarkPlugins={[remarkGfm]}>
      {analysis}
    </ReactMarkdown>
  </div>
)}
            </div>

            {mcpFindings && (
              <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5 sm:p-7">
                <div>
                  <p className="text-sm font-medium text-cyan-400">
                    EVIDENCETRAIL
                  </p>
                  <h2 className="mt-2 text-2xl font-bold">
                    MCP investigation details
                  </h2>
                  {mcpFindings.unavailable && (
  <div
    role="alert"
    className="mt-4 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4"
  >
    <p className="font-semibold text-amber-300">
      MCP checks unavailable
    </p>
    <p className="mt-2 text-sm leading-6 text-slate-300">
      {mcpFindings.error ??
        "The MCP server could not be reached. No MCP checks were completed."}
    </p>
    <p className="mt-2 text-sm text-slate-400">
      The AI explanation may still be available, but it does not replace
      the missing MCP checks.
    </p>
  </div>
)}
                  <p className="mt-2 text-sm leading-6 text-slate-400">
                    These are the tool results returned by your MCP
                    server for this investigation.
                  </p>
                </div>
<EvidenceSummary findings={mcpFindings} />
                <div className="mt-5 grid gap-3 sm:grid-cols-3">
                  {[
                    "extract_indicators",
                    "check_message",
                    "check_url_safely",
                  ].map((tool) => {
                    const called = toolsCalled.includes(tool);

                    return (
                      <div
                        key={tool}
                        className="rounded-xl border border-slate-800 bg-slate-950/70 p-4"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span
                            className={`h-2 w-2 rounded-full ${
                              called ? "bg-emerald-400" : "bg-slate-600"
                            }`}
                          />
                          <span className="text-xs text-slate-400">
                            {called ? "Called" : "Not called"}
                          </span>
                        </div>
                        <p className="mt-3 break-all text-sm font-medium text-slate-200">
                          {tool}
                        </p>
                      </div>
                    );
                  })}
                </div>

                <div className="mt-5 space-y-3">
                  {mcpFindings.extraction && (
                    <ResultCard
                      title="Indicator extraction"
                      description="Signals and indicators found in the submitted message."
                      result={mcpFindings.extraction}
                    />
                  )}

                  {mcpFindings.messageCheck && (
                    <ResultCard
                      title="Message assessment"
                      description="Output from the deterministic message-check tool."
                      result={mcpFindings.messageCheck}
                    />
                  )}

                  {mcpFindings.urlChecks?.length ? (
                    mcpFindings.urlChecks.map((check, index) => (
                      <ResultCard
                        key={`${check.url}-${index}`}
                        title={`URL inspection ${index + 1}`}
                        description={check.url}
                        result={check.error ?? check.result}
                      />
                    ))
                  ) : (
                    <div className="rounded-xl border border-slate-800 p-4 text-sm text-slate-400">
                      No URL inspection results were returned for this
                      message.
                    </div>
                  )}
                </div>
              </div>
            )}

            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 text-sm leading-6 text-slate-400">
              <strong className="text-slate-200">
                Safety reminder:
              </strong>{" "}
              ScamLens provides advisory findings, not a guarantee that
              a message is fraudulent or safe. Do not click suspicious
              links or share passwords, PINs, or OTPs. Verify claims
              through official channels.
            </div>
          </section>
        )}

        <footer className="mt-10 border-t border-slate-800 py-6 text-center text-xs leading-6 text-slate-500">
          ScamLens · Evidence first, safer decisions
          <br />
          Automated checks can miss threats. Always verify independently.
        </footer>
      </div>
    </main>
  );
}