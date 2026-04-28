import { spawn } from "child_process";
import chalk from "chalk";

const OLLAMA_MODEL = "llama3.2:latest";

const GROQ_MODEL = "llama-3.3-70b-versatile";

async function analyzeWithGroq(findings, projectName) {
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) {
    throw new Error("GROQ_API_KEY no configurada");
  }

  const summary = findings
    .map((f) => `- ${f.description} (${f.severity}) en ${f.file || f.package}`)
    .join("\n");

  const prompt = `
Eres Secura, un asistente de seguridad para proyectos Node.js.
Analiza los siguientes hallazgos encontrados en el proyecto "${projectName}":

${summary}

Proporciona:
1. Una evaluación del nivel de riesgo general (bajo/medio/alto/crítico)
2. Los hallazgos más críticos que deben abordarse primero
3. Recomendaciones accionables para cada uno

Sé conciso y práctico. Usa español.
`.trim();

  const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: GROQ_MODEL,
      messages: [
        {
          role: "system",
          content: "Eres Secura, un asistente de seguridad para proyectos Node.js."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      temperature: 0.3,
      max_tokens: 1024,
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Groq API error: ${response.status} - ${error}`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || "Sin respuesta del modelo";
}

async function analyzeWithOllama(findings, projectName) {
  const summary = findings
    .map((f) => `- ${f.description} (${f.severity}) en ${f.file || f.package}`)
    .join("\n");

  const prompt = `
Eres Secura, un asistente de seguridad para proyectos Node.js.
Analiza los siguientes hallazgos encontrados en el proyecto "${projectName}":

${summary}

Proporciona:
1. Una evaluación del nivel de riesgo general (bajo/medio/alto/crítico)
2. Los hallazgos más críticos que deben abordarse primero
3. Recomendaciones accionables para cada uno

Sé conciso y práctico. Usa español.
`.trim();

  return new Promise((resolve, reject) => {
    const proc = spawn("ollama", ["run", OLLAMA_MODEL], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    let output = "";
    let errorOutput = "";

    proc.stdout.on("data", (data) => {
      output += data.toString();
    });

    proc.stderr.on("data", (data) => {
      errorOutput += data.toString();
    });

    proc.on("close", (code) => {
      if (code === 0) {
        resolve(output.trim());
      } else {
        reject(new Error(`Ollama error: ${errorOutput}`));
      }
    });

    proc.on("error", (err) => {
      reject(err);
    });

    proc.stdin.write(prompt);
    proc.stdin.end();
  });
}

export async function analyzeWithAI(findings, projectName, provider = "auto") {
  if (!findings || findings.length === 0) {
    return "No se encontraron hallazgos para analizar.";
  }

  const groqKey = process.env.GROQ_API_KEY;
  const ollamaAvailable = await isOllamaAvailable();

  let selectedProvider = provider;

  if (provider === "auto") {
    if (groqKey) {
      selectedProvider = "groq";
    } else if (ollamaAvailable) {
      selectedProvider = "ollama";
    } else {
      throw new Error("No hay proveedor de IA disponible. Configurá GROQ_API_KEY o installá Ollama.");
    }
  }

  try {
    if (selectedProvider === "groq") {
      console.log(chalk.gray("  → Usando Groq API..."));
      return await analyzeWithGroq(findings, projectName);
    } else {
      console.log(chalk.gray("  → Usando Ollama local..."));
      return await analyzeWithOllama(findings, projectName);
    }
  } catch (err) {
    if (selectedProvider === "groq" && ollamaAvailable) {
      console.log(chalk.yellow(`  ⚠️  Groq falló, intentando Ollama...`));
      return await analyzeWithOllama(findings, projectName);
    }
    throw err;
  }
}

export async function isOllamaAvailable() {
  return new Promise((resolve) => {
    const proc = spawn("ollama", ["list"], { stdio: "ignore" });
    proc.on("close", (code) => {
      resolve(code === 0);
    });
    proc.on("error", () => {
      resolve(false);
    });
  });
}

export function getAvailableProviders() {
  const providers = [];
  
  if (process.env.GROQ_API_KEY) {
    providers.push("groq");
  }
  
  return providers;
}