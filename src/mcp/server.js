import { createInterface } from "readline";
import { handleMCPRequest } from "./handler.js";
import { createResponse, createError, isMCPRequest, MCPErrorCodes } from "./types.js";

let requestId = 0;

function sendMessage(message) {
  process.stdout.write(JSON.stringify(message) + "\n");
}

async function processLine(line) {
  if (!line.trim()) return;

  let request;
  try {
    request = JSON.parse(line);
  } catch (e) {
    sendMessage(createError(null, MCPErrorCodes.PARSE_ERROR, "Invalid JSON"));
    return;
  }

  if (!isMCPRequest(request)) {
    sendMessage(createError(request.id, MCPErrorCodes.INVALID_REQUEST, "Invalid MCP request"));
    return;
  }

  const id = request.id ?? requestId++;

  try {
    const result = await handleMCPRequest(request.method, request.params || {});
    sendMessage(createResponse(id, result));
  } catch (err) {
    sendMessage(createError(id, MCPErrorCodes.INTERNAL_ERROR, err.message));
  }
}

export function startMCPServer() {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  rl.on("line", processLine);
}