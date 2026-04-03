# Secura 🔐

Security scanner para proyectos Node.js con análisis de patrones sospechosos y soporte para IA local.

## Características

- **Escaneo de package.json scripts** - Detecta patrones peligrosos en lifecycle scripts (preinstall, postinstall, etc.)
- **Escaneo de código fuente** - Analiza archivos JS/TS en busca de patrones de malware
- **Escaneo de node_modules** - Analiza archivos de entrada de paquetes instalados
- **Análisis con IA** - Integración con Groq API u Ollama local para análisis contextual de hallazgos
- **Diagnóstico de entorno** - Analiza configuraciones de seguridad y .gitignore
- **Hardening automático** - Aplica recomendaciones de seguridad con confirmación
- **Exportación JSON** - Genera reportes en formato JSON

## Instalación

```bash
# Con Bun (recomendado)
bun install

# Con npm
npm install
```

## Uso

```bash
# Escanear proyecto actual
bun src/index.js

# Escanear ruta específica
bun src/index.js /path/a/proyecto

# Sin análisis de IA
bun src/index.js . --no-ai

# Solo una fase
bun src/index.js . --only scripts    # solo package.json
bun src/index.js . --only source      # solo código fuente
bun src/index.js . --only modules     # solo node_modules

# Exportar JSON
bun src/index.js . --json reporte.json
```

## Opciones

| Flag | Descripción |
|------|-------------|
| `[path]` | Ruta del proyecto a escanear (default: `.`) |
| `--no-ai` | Desactivar análisis con IA |
| `--ai-provider <provider>` | Proveedor: `groq`, `ollama` o `auto` (default) |
| `--json [file]` | Exportar reporte en JSON |
| `--only <phase>` | Escanear solo: `scripts`, `source` o `modules` |
| `--audit-env` | Incluir diagnóstico de entorno |
| `--skip-gitignore` | No analizar .gitignore |
| `--apply` | Aplicar hardening automáticamente sin preguntar |
| `--pm <manager>` | Forzar package manager: npm, yarn, pnpm |

## Diagnóstico de Entorno

El flag `--audit-env` analiza la configuración de seguridad del proyecto:

```bash
bun src/index.js . --audit-env
```

### Configuraciones analizadas

| Config | Recomendado | Descripción |
|--------|-------------|-------------|
| `ignore-scripts` | true | Previene scripts maliciosos en install |
| `audit-level` | high | Detecta vulnerabilidades de severidad alta |
| `fund` | false | Desactiva mensajes de donation |
| `engine-strict` | false | Exige versiones de Node matching engines |
| `audit` | true | Ejecuta npm audit automáticamente |
| `legacy-peer-deps` | false | Evita conflictos de peer deps silenciados |

### .gitignore

Analiza que archivos sensibles no estén subidos al repositorio:

- `.env`, `.env.local` (variables de entorno)
- `id_rsa`, `id_ed25519` (claves SSH)
- `credentials.json`, `secrets.json` (credenciales)
- `.npmrc`, `.yarnrc` (configuraciones con tokens)

### Hardening Automático

El scanner puede aplicar las recomendaciones automáticamente:

```bash
# Con confirmación interactiva
bun src/index.js . --audit-env

# Sin confirmación (para CI/CD)
bun src/index.js . --audit-env --apply
```

Archivos modificados:
- `.npmrc` - Configuraciones de seguridad
- `.gitignore` - Archivos sensibles a ignorar
- `package.json` - engineStrict

## MCP (Model Context Protocol)

Secura puede ser usado como servidor MCP para integrar con Claude, Cursor, Windsurf:

```bash
# Iniciar servidor MCP
bun src/index.js --mcp
```

### Uso con Claude

En tu config de MCP, agregar:

```json
{
  "mcpServers": {
    "secura": {
      "command": "node",
      "args": ["/path/to/secura/src/index.js", "--mcp"]
    }
  }
}
```

### Métodos MCP

| Método | Descripción |
|--------|-------------|
| `healthcheck` | Verificar que el servidor funcione |
| `scan` | Escanear proyecto |
| `scan-with-env` | Escanear + diagnóstico de entorno |
| `apply-hardening` | Aplicar hardening |
| `get-patterns` | Listar patrones de detección |

### Ejemplo de request

```json
{"jsonrpc":"2.0","id":1,"method":"scan","params":{"path":"/project"}}
```

### Ejemplo de response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "projectPath": "/project",
    "totalFindings": 5,
    "summary": {
      "critical": 1,
      "high": 2,
      "medium": 2,
      "riskLevel": "HIGH"
    }
  }
}
```

## Estructura del Proyecto

```
secura/
├── src/
│   ├── index.js              # CLI entrypoint
│   ├── scanners/
│   │   ├── scripts.js        # package.json + node_modules scripts
│   │   └── files.js          # código fuente
│   ├── patterns/
│   │   └── index.js          # Biblioteca de patrones
│   ├── auditors/
│   │   ├── environment.js    # Análisis de configuraciones
│   │   └── gitignore.js      # Análisis de .gitignore
│   ├── hardening/
│   │   └── apply.js          # Aplicar recomendaciones
│   ├── mcp/
│   │   ├── server.js         # Servidor MCP standalone
│   │   ├── handler.js        # Manejador de comandos
│   │   └── types.js          # Tipos MCP
│   ├── reporters/
│   │   └── console.js        # Output formateado
│   └── utils/
│       └── ai.js             # Integración Groq/Ollama
├── mcp-server.js             # Entry point para --mcp
├── package.json
└── README.md
```

## License

MIT