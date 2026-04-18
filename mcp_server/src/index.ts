import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { Pool } from "pg";
import util from "node:util";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL ?? "postgresql://jonathanduron@localhost:5432/cyber_copilot"
});

const server = new McpServer({
  name: "cyber-kb",
  version: "1.0.0"
});

server.registerTool(
  "search_kb",
  {
    title: "Search knowledge base",
    description: "Search the MITRE ATT&CK knowledge base by keyword to find relevant threats, techniques, and mitigations",
    inputSchema: {
      query: z.string().describe("Alert description or threat keyword"),
      limit: z.number().optional().default(5).describe("Max results to return")
    }
  },
  async ({ query, limit }) => {
    try {
      const tsQuery = query
        .replace(/[^\w\s]/g, '')
        .trim()
        .split(/\s+/)
        .filter(w => w.length > 2)
        .join(' & ');

      if (!tsQuery) {
        return { content: [{ type: "text", text: "[]" }] };
      }

      const { rows } = await pool.query(`
        SELECT
          ke.title,
          ke.content,
          ke.entry_type,
          kd.name AS domain,
          ts_rank(ke.search_vector, to_tsquery('english', $1)) AS score
        FROM knowledge_entries ke
        LEFT JOIN knowledge_domains kd ON ke.domain_id = kd.id
        WHERE ke.search_vector @@ to_tsquery('english', $1)
        ORDER BY score DESC
        LIMIT $2
      `, [tsQuery, limit]);

      return {
        content: [{ type: "text", text: JSON.stringify(rows, null, 2) }]
      };
    } catch (error) {
      const message = error instanceof Error ? (error.stack || error.message) : util.inspect(error);
      console.error("search_kb failed:", message);
      return {
        content: [{ type: "text", text: message }],
        isError: true,
      };
    }
  }
);

server.registerTool(
  "get_technique",
  {
    title: "Get technique details",
    description: "Fetch full details of a specific MITRE ATT&CK technique by name",
    inputSchema: {
      title: z.string().describe("Technique name, e.g. 'Brute Force' or 'Phishing'")
    }
  },
  async ({ title }) => {
    try {
      const { rows } = await pool.query(`
        SELECT ke.*, kd.name AS domain
        FROM knowledge_entries ke
        LEFT JOIN knowledge_domains kd ON ke.domain_id = kd.id
        WHERE ke.title ILIKE $1
        LIMIT 1
      `, [`%${title}%`]);

      if (!rows.length) {
        return { content: [{ type: "text", text: "Technique not found" }] };
      }

      return {
        content: [{ type: "text", text: JSON.stringify(rows[0], null, 2) }]
      };
    } catch (error) {
      const message = error instanceof Error ? (error.stack || error.message) : util.inspect(error);
      console.error("get_technique failed:", message);
      return {
        content: [{ type: "text", text: message }],
        isError: true,
      };
    }
  }
);

server.registerTool(
  "list_tactics",
  {
    title: "List ATT&CK tactics",
    description: "List all MITRE ATT&CK tactic domains (e.g. Initial Access, Persistence, Exfiltration)",
    inputSchema: {}
  },
  async () => {
    try {
      const { rows } = await pool.query(
        "SELECT id, name, description FROM knowledge_domains ORDER BY name"
      );
      return {
        content: [{ type: "text", text: JSON.stringify(rows, null, 2) }]
      };
    } catch (error) {
      const message = error instanceof Error ? (error.stack || error.message) : util.inspect(error);
      console.error("list_tactics failed:", message);
      return {
        content: [{ type: "text", text: message }],
        isError: true,
      };
    }
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
