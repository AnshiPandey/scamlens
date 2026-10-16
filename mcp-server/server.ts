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

function createMcpServer() {
  const server = new McpServer({
    name: "scamlens-mcp-server",
    version: "1.0.0",
  });

  // TOOL 1: Extract suspicious indicators from a message.
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
      const urls = [
        ...new Set(
          (message.match(/https?:\/\/[^\s<>"']+/gi) ?? []).map((url) =>
            url.replace(/[),.!?;]+$/, "")
          )
        ),
      ];

      const phoneNumbers = [
        ...new Set(
          message.match(/(?:\+?\d[\d\s().-]{7,}\d)/g) ?? []
        ),
      ].map((phone) => phone.trim());

      const indicators: string[] = [];

      if (/urgent|immediately|act now|final warning|within \d+ hours/i.test(message)) {
        indicators.push("Urgency or pressure language");
      }

      if (/password|OTP|one.time.password|verification code|PIN/i.test(message)) {
        indicators.push("Sensitive authentication information mentioned");
      }

      if (/prize|lottery|you have won|claim your reward/i.test(message)) {
        indicators.push("Prize or reward claim");
      }

      if (/click here|verify your account|account.{0,30}blocked/i.test(message)) {
        indicators.push("Account verification or link-click pressure");
      }

      if (/send money|transfer funds|pay immediately|gift card/i.test(message)) {
        indicators.push("Payment or money-transfer pressure");
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                urls,
                phoneNumbers,
                indicators,
                note: "These are extracted signals and heuristics, not proof of fraud.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // TOOL 2: Inspect a URL without visiting it.
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
        const hostname = parsed.hostname.toLowerCase();
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
            (hostname.startsWith("fc") ||
              hostname.startsWith("fd") ||
              hostname.startsWith("fe80:")));

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

        if (hostname.split(".").some((label) => label.length > 0 && label.length > 40)) {
          findings.push("Hostname contains an unusually long label");
        }

        if (hostname.match(/\d+\.\d+\.\d+\.\d+/)) {
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
          note: "Provide a complete URL, including its protocol, for structural inspection.",
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

  // Keep the original tool for backward compatibility.
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
      const indicators: string[] = [];

      if (/urgent|immediately|act now|final warning/i.test(message)) {
        indicators.push("Urgency or pressure language");
      }

      if (/password|otp|one.time.password|verification code/i.test(message)) {
        indicators.push("Sensitive authentication information mentioned");
      }

      if (/prize|lottery|you have won|claim your reward/i.test(message)) {
        indicators.push("Prize or reward claim");
      }

      if (/click here|verify your account|account.{0,20}blocked/i.test(message)) {
        indicators.push("Account verification or link-click pressure");
      }

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

app.get("/", (_req, res) => {
  res.json({
    name: "ScamLens MCP Server",
    status: "running",
    endpoint: "/mcp",
  });
});

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

  await transport.handleRequest(req, res, req.body);
});

app.get("/mcp", (_req, res) => {
  res.status(405).set("Allow", "POST").send("Method Not Allowed");
});

app.delete("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  const transport = sessionId ? transports[sessionId] : undefined;

  if (!transport) {
    res.status(404).send("Unknown MCP session");
    return;
  }

  await transport.close();
  res.status(200).send("Session closed");
});

const port = Number(process.env.MCP_PORT ?? 3001);

app.listen(port, "127.0.0.1", () => {
  console.log(`ScamLens MCP server listening on http://127.0.0.1:${port}/mcp`);
});
