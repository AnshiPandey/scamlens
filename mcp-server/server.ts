import express from "express";
import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const app = express();
app.use(express.json({ limit: "100kb" }));

const transports: Record<string, StreamableHTTPServerTransport> = {};

// These patterns identify possible warning signs; they do not prove fraud.
const urgencyPattern =
  /\b(urgent|urgently|immediately|act\s+now|act\s+immediately|final\s+warning|last\s+chance|within\s+\d+\s*(?:hours?|hrs?|minutes?|mins?|seconds?|days?)|in\s+\d+\s*(?:hours?|hrs?|minutes?|mins?|seconds?|days?)|expires?\s+in\s+\d+|deadline|limited\s+time|today\s+only|before\s+your\s+account)\b/i;

const shortDeadlinePattern =
  /\b\d+\s*[- ]?\s*(?:minute|min|second|sec)\s*(?:deadline|left|remaining|to\s+claim|to\s+respond)?\b|\b(?:claim|respond|verify|pay|act)\s+(?:within|in)\s+\d+\s*(?:hours?|hrs?|minutes?|mins?|seconds?|secs?)\b/i;

const authenticationPattern =
  /\b(password|passcode|OTP|one[- ]time password|verification code|PIN|CVV|security code)\b/i;

const prizePattern =
  /\b(prize|lottery|you have won|you['’]?ve won|winner|winning|claim your reward|reward|voucher|lucky draw|cash prize|won ₹?[\d,]+)\b/i;

const accountPattern =
  /\b(click here|click the link|verify your account|account.{0,30}blocked|account.{0,30}suspend|KYC|know your customer|bank.{0,30}verification)\b/i;

const paymentPattern =
  /\b(send money|transfer funds|pay immediately|gift card|money transfer|wire transfer|make a payment)\b/i;

const advanceFeePattern =
  /\b(processing fee|claim fee|advance fee|upfront fee|pay to claim|pay to receive|pay.{0,30}(?:release|unlock|receive|claim)|fee.{0,30}(?:prize|reward|winnings)|pay ₹?\s?[\d,]+)\b/i;

function extractIndicators(message: string): string[] {
  const indicators: string[] = [];

  if (urgencyPattern.test(message) || shortDeadlinePattern.test(message)) {
    indicators.push("Urgency or pressure language");
  }

  if (authenticationPattern.test(message)) {
    indicators.push("Sensitive authentication information mentioned");
  }

  if (prizePattern.test(message)) {
    indicators.push("Prize or reward claim");
  }

  if (accountPattern.test(message)) {
    indicators.push("Account verification or link-click pressure");
  }

  if (paymentPattern.test(message)) {
    indicators.push("Payment or money-transfer pressure");
  }

  if (advanceFeePattern.test(message)) {
    indicators.push("Possible advance-fee requirement");
  }

  return indicators;
}

function extractUrls(message: string): string[] {
  const matches = message.match(/https?:\/\/[^\s<>"')\]]+/gi) ?? [];

  return [
    ...new Set(matches.map((url) => url.replace(/[),.!?;:]+$/, ""))),
  ];
}

function extractPhoneNumbers(message: string): string[] {
  const matches = message.match(/(?:\+\s?)?\d[\d\s().-]{7,}\d/g) ?? [];
  return [...new Set(matches.map((phone) => phone.trim()))];
}

function createMcpServer() {
  const server = new McpServer({
    name: "scamlens-mcp-server",
    version: "1.0.0",
  });

  // TOOL 1: Extract URLs, phone numbers, and heuristic warning signs.
  server.registerTool(
    "extract_indicators",
    {
      title: "Extract Scam Indicators",
      description:
        "Extract URLs, phone numbers, and possible scam warning signs from text. Does not prove fraud.",
      inputSchema: {
        message: z.string().min(1).max(5000),
      },
    },
    async ({ message }) => {
      const urls = extractUrls(message);
      const phoneNumbers = extractPhoneNumbers(message);
      const indicators = extractIndicators(message);

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                urls,
                phoneNumbers,
                indicators,
                note:
                  "These are extracted signals and heuristics, not proof of fraud.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // TOOL 2: Inspect URL structure without visiting the destination.
  server.registerTool(
    "check_url_safely",
    {
      title: "Inspect URL Safely",
      description:
        "Inspect URL structure without opening the URL or making a network request. This is not a reputation check.",
      inputSchema: {
        url: z.string().min(1).max(2048),
      },
    },
    async ({ url }) => {
      let result: Record<string, unknown>;
 try {
        const parsed = new URL(url);
        const findings: string[] = [];
        const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
        const ipVersion = isIP(hostname);

        const privateOrLocal =
          hostname === "localhost" ||
          hostname.endsWith(".localhost") ||
          hostname.endsWith(".local") ||
          hostname === "0.0.0.0" ||
          hostname === "::1" ||
          /^127\./.test(hostname) ||
          /^10\./.test(hostname) ||
          /^192\.168\./.test(hostname) ||
          /^169\.254\./.test(hostname) ||
          /^172\.(1[6-9]|2\d|3[01])\./.test(hostname) ||
          (ipVersion === 6 &&
            (/^(fc|fd)/i.test(hostname) || /^fe80:/i.test(hostname)));

        if (!["http:", "https:"].includes(parsed.protocol)) {
          findings.push("URL uses a non-HTTP(S) protocol");
        }

        if (parsed.protocol === "http:") {
          findings.push("Connection does not use HTTPS");
        }

        if (parsed.username || parsed.password) {
          findings.push("URL contains embedded username or password fields");
        }

        if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
          findings.push("Hostname contains an internationalized domain label");
        }

        if (hostname.split(".").some((label) => label.length > 40)) {
          findings.push("Hostname contains an unusually long label");
        }

        if (ipVersion === 4) {
          findings.push("URL uses an IPv4 address instead of a domain name");
        }

        const shorteners = [
          "bit.ly",
          "tinyurl.com",
          "t.co",
          "is.gd",
          "cutt.ly",
          "rb.gy",
        ];

            if (shorteners.includes(hostname)) {
          findings.push("URL uses a known link-shortening domain");
        }

        if (privateOrLocal) {
          findings.push("URL points to a local or private network address");
        }

        const isReservedExampleDomain =
          hostname === "example.com" ||
          hostname.endsWith(".example.com") ||
          hostname === "example.org" ||
          hostname.endsWith(".example.org") ||
          hostname === "example.net" ||
          hostname.endsWith(".example.net");

        if (isReservedExampleDomain) {
          findings.push(
            "Hostname uses a reserved example domain commonly used for documentation and testing; this does not establish that a real phishing site exists"
          );
        }

        if (/\b(sbi|kyc|verify|verification|bank|account)\b/i.test(hostname)) {
          findings.push(
            "Hostname contains banking or verification-related keywords; this is a structural heuristic, not proof of impersonation"
          );
        }

        result = {
          validUrl: true,
          hostname,
          protocol: parsed.protocol,
          findings,
          localOrPrivateAddress: privateOrLocal,
          reputationStatus: "not_checked",
          networkRequestMade: false,
          note:
            "Only URL structure was inspected. No website was opened and no external reputation service was queried. Findings do not establish whether a URL is malicious or safe.",
        };
      } catch {
        result = {
          validUrl: false,
          findings: ["Input could not be parsed as an absolute URL"],
          reputationStatus: "not_checked",
          networkRequestMade: false,
          note:
            "Provide a complete URL, including its protocol, for structural inspection.",
        };
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    }
  );

   // TOOL 3: Assess message warning signs using deterministic heuristics.
  server.registerTool(
    "check_message",
    {
      title: "Check Message",
      description:
        "Analyze a message for basic scam warning signs. Returns observed indicators, not a definitive verdict.",
      inputSchema: {
        message: z.string().min(1).max(5000),
      },
    },
    async ({ message }) => {
      const indicators = extractIndicators(message);

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                indicators,
                assessment:
                  indicators.length >= 2
                    ? "high_concern"
                    : indicators.length === 1
                      ? "needs_review"
                      : "inconclusive",
                disclaimer:
                  "These are heuristic warning signs, not proof of fraud. No external reputation check was performed.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  return server;
}

// Basic server status endpoint.
app.get("/", (_req, res) => {
  res.json({
    name: "ScamLens MCP Server",
    status: "running",
    endpoint: "/mcp",
  });
});

// Initialize MCP sessions and handle requests.
app.post("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  let transport = sessionId ? transports[sessionId] : undefined;

  if (!transport && isInitializeRequest(req.body)) {
    const newTransport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => {
        transports[id] = newTransport;
      },
    });

    newTransport.onclose = () => {
      if (newTransport.sessionId) {
        delete transports[newTransport.sessionId];
      }
    };

    const server = createMcpServer();
    await server.connect(newTransport);
    transport = newTransport;
  }

  if (!transport) {
    res.status(400).json({
      error: "No valid MCP session. Initialize the MCP connection first.",
    });
    return;
  }

  try {
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("MCP request failed:", error);

    if (!res.headersSent) {
      res.status(500).json({ error: "Internal MCP server error" });
    }
  }
});

// This server does not offer an SSE stream through GET /mcp.
app.get("/mcp", (_req, res) => {
  res.status(405).set("Allow", "POST, DELETE").send("Method Not Allowed");
});

// Close an existing MCP session.
app.delete("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  const transport = sessionId ? transports[sessionId] : undefined;

  if (!transport) {
    res.status(404).send("Unknown MCP session");
    return;
  }

  try {
    await transport.close();
    res.status(200).send("Session closed");
  } catch (error) {
    console.error("Failed to close MCP session:", error);
    res.status(500).send("Could not close MCP session");
  }
});

const port = Number(process.env.PORT ?? process.env.MCP_PORT ?? 3001);

app.listen(port, "0.0.0.0", () => {
  console.log(`ScamLens MCP server listening on port ${port}`);
});
