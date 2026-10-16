
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

async function main() {
  const client = new Client({
    name: "scamlens-test-client",
    version: "1.0.0",
  });

  const transport = new StreamableHTTPClientTransport(
    new URL("http://127.0.0.1:3001/mcp")
  );

  try {
    await client.connect(transport);
    console.log("Connected to ScamLens MCP server!");

    const tools = await client.listTools();
    console.log("\nAvailable tools:");
    console.log(tools.tools.map((tool) => tool.name));

    console.log("\n--- Test 1: Extract indicators ---");
    const extraction = await client.callTool({
      name: "extract_indicators",
      arguments: {
        message:
          "URGENT! Your account will be blocked. Verify your password at https://example.com/login immediately.",
      },
    });
    console.log(JSON.stringify(extraction, null, 2));

    console.log("\n--- Test 2: Inspect URL safely ---");
    const urlCheck = await client.callTool({
      name: "check_url_safely",
      arguments: {
        url: "http://example.com/login",
      },
    });
    console.log(JSON.stringify(urlCheck, null, 2));

    console.log("\n--- Test 3: Original tool still works ---");
    const original = await client.callTool({
      name: "check_message",
      arguments: {
        message: "You have won a prize. Claim your reward immediately!",
      },
    });
    console.log(JSON.stringify(original, null, 2));
  } catch (error) {
    console.error("MCP client error:", error);
    process.exitCode = 1;
  } finally {
    await client.close();
  }
}

main();
