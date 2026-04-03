export const MCPMethods = {
  SCAN: "scan",
  SCAN_WITH_ENV: "scan-with-env",
  APPLY_HARDENING: "apply-hardening",
  HEALTHCHECK: "healthcheck",
  GET_PATTERNS: "get-patterns",
};

export const MCPErrorCodes = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
};

export function createResponse(id, result) {
  return { jsonrpc: "2.0", id, result };
}

export function createError(id, code, message, data = null) {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code,
      message,
      data,
    },
  };
}

export function isMCPRequest(obj) {
  return (
    obj &&
    obj.jsonrpc === "2.0" &&
    obj.method &&
    typeof obj.method === "string"
  );
}