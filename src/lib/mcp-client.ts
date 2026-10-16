
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const MCP_SERVER_URL =
  process.env.MCP_SERVER_URL || "http://127.0.0.1:3001/mcp";

export async function investigateWithMCP(message: string) {
  const client = new Client({
    name: "scamlens-web-app",
    version: "1.0.0",
  });

  const transport = new StreamableHTTPClientTransport(
    new URL(MCP_SERVER_URL)
  );

  try {
    await client.connect(transport);

    // 1. Extract URLs and suspicious indicators.
    const extraction = await client.callTool({
      name: "extract_indicators",
      arguments: { message },
    });

    // 2. Run the existing deterministic message check.
    const messageCheck = await client.callTool({
      name: "check_message",
      arguments: { message },
    });

    // 3. Inspect URLs found in the submitted message.
    const urls = [
      ...new Set(
        message.match(/https?:\/\/[^\s<>"']+/gi) || []
      ),
    ].slice(0, 5);

    const urlChecks = [];

    for (const url of urls) {
      const cleanedUrl = url.replace(/[),.!?;:]+$/, "");

      try {
        const result = await client.callTool({
          name: "check_url_safely",
          arguments: { url: cleanedUrl },
        });

        urlChecks.push({
          url: cleanedUrl,
          result,
        });
      } catch (error) {
        urlChecks.push({
          url: cleanedUrl,
          error:
            error instanceof Error
              ? error.message
              : "URL inspection failed.",
        });
      }
    }

    return {
      toolsCalled: [
        "extract_indicators",
        "check_message",
        ...(urls.length > 0 ? ["check_url_safely"] : []),
      ],
      extraction,
      messageCheck,
      urlChecks,
    };
  } finally {
    await client.close();
  }
}
