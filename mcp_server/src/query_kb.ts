import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

type QueryArgs = {
  tool: string;
  query: string;
  limit: number;
};

function parseArgs(argv: string[]): QueryArgs {
  const args: Record<string, string> = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      continue;
    }
    args[token.slice(2)] = argv[index + 1] ?? "";
    index += 1;
  }
  return {
    tool: args.tool || "search_kb",
    query: args.query || "",
    limit: Number(args.limit || "5"),
  };
}

function getServerCommand() {
  const npmCmd = process.platform === "win32" ? "npm.cmd" : "npm";
  return {
    command: npmCmd,
    args: ["run", "--silent", "dev"],
    env: {
      ...process.env,
    },
    stderr: "inherit" as const,
  };
}

async function main() {
  const { tool, query, limit } = parseArgs(process.argv.slice(2));
  const client = new Client(
    {
      name: "cyber-kb-query-client",
      version: "1.0.0",
    },
    {
      capabilities: {},
    }
  );

  const transport = new StdioClientTransport(getServerCommand());
  await client.connect(transport);

  try {
    const result = await client.callTool({
      name: tool,
      arguments: {
        query,
        limit,
      },
    });
    process.stdout.write(JSON.stringify(result));
  } finally {
    await client.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
