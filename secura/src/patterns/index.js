export const patterns = [
  // — EJECUCIÓN DE CÓDIGO —
  {
    id: "eval-obfuscated",
    severity: "high",
    category: "code-execution",
    description: "eval() ejecutando contenido codificado en base64",
    regex: /eval\s*\(\s*(Buffer\.from|atob)\s*\(/,
    explanation:
      "Patrón clásico de malware: decodifica un payload oculto y lo ejecuta.",
  },
  {
    id: "eval-plain",
    severity: "medium",
    category: "code-execution",
    description: "eval() con variable o expresión dinámica",
    regex: /eval\s*\(\s*(?!['"`])/,
    explanation:
      "eval() ejecutando contenido dinámico. Puede ser legítimo pero es un vector de ataque común.",
  },
  {
    id: "new-function",
    severity: "medium",
    category: "code-execution",
    description: "new Function() para ejecución dinámica de código",
    regex: /new\s+Function\s*\(/,
    explanation: "Equivalente a eval(). Permite ejecutar código arbitrario en runtime.",
  },
  {
    id: "vm-run-context",
    severity: "medium",
    category: "code-execution",
    description: "vm.runInThisContext() o vm.runInNewContext()",
    regex: /vm\.run(InThisContext|InNewContext|InContext)\s*\(/,
    explanation: "Ejecuta código en el contexto de Node. Puede bypassear protecciones.",
  },
  // — EXFILTRACIÓN DE DATOS —
  {
    id: "ssh-key-access",
    severity: "high",
    category: "data-exfiltration",
    description: "Acceso a claves SSH del usuario",
    regex: /['"](\.ssh|id_rsa|id_ed25519|known_hosts|authorized_keys)['"]/,
    explanation:
      "Intento de leer claves SSH privadas. Un atacante podría exfiltrarlas.",
  },
  {
    id: "env-file-access",
    severity: "high",
    category: "data-exfiltration",
    description: "Lectura directa de archivos .env",
    regex: /readFile(Sync)?\s*\([^)]*['"]\.env['"]/,
    explanation:
      "Lectura de archivos .env que pueden contener API keys y credenciales.",
  },
  {
    id: "process-env-exfil",
    severity: "medium",
    category: "data-exfiltration",
    description: "process.env completo enviado a red",
    regex: /JSON\.stringify\s*\(\s*process\.env\s*\)/,
    explanation:
      "Serializa todas las variables de entorno para enviarlas a un servidor externo.",
  },
  {
    id: "home-dir-access",
    severity: "medium",
    category: "data-exfiltration",
    description: "Acceso al directorio home del usuario",
    regex: /(os\.homedir\(\)|process\.env\.HOME|~\/)/,
    explanation:
      "Accede al directorio personal del usuario, donde se guardan datos sensibles.",
  },
  {
    id: "git-credentials-access",
    severity: "high",
    category: "data-exfiltration",
    description: "Acceso a credenciales de Git",
    regex: /\.git-credentials|git[_-]credentials/,
    explanation:
      "Intento de leer credenciales de Git almacenadas.",
  },
  {
    id: "npm-config-access",
    severity: "high",
    category: "data-exfiltration",
    description: "Acceso a configuración de npm (tokens)",
    regex: /process\.env\.npm_config_|process\.env\./,
    explanation:
      "Acceso a tokens de npm o variables de configuración.",
  },
  // — RED —
  {
    id: "network-in-lifecycle",
    severity: "high",
    category: "network",
    description: "Solicitud de red en script de lifecycle",
    regex: /(curl|wget)\s+https?:\/\//,
    explanation:
      "Descarga contenido de internet durante la instalación. Puede traer malware.",
  },
  {
    id: "dns-lookup-suspicious",
    severity: "medium",
    category: "network",
    description: "DNS lookup hardcodeado a dominio externo",
    regex: /dns\.lookup\s*\(\s*['"][^'"]+\.[^'"]+['"]/,
    explanation:
      "Resolución DNS a dominio hardcodeado. Técnica usada para exfiltrar datos.",
  },
  {
    id: "fetch-external",
    severity: "medium",
    category: "network",
    description: "fetch() o http.request() a URL hardcodeada",
    regex: /(fetch|http\.request|https\.request)\s*\(\s*['"](http|https):\/\//,
    explanation:
      "Request a URL externa hardcodeada. En scripts de instalación es sospechoso.",
  },
  // — EJECUCIÓN DE SISTEMA —
  {
    id: "child-process-exec",
    severity: "high",
    category: "system-execution",
    description: "child_process.exec() con string dinámico",
    regex: /(?:exec|execSync)\s*\(\s*(?!['"`])/,
    explanation:
      "Ejecuta comandos del sistema con contenido dinámico. Riesgo de command injection.",
  },
  {
    id: "shell-pipe",
    severity: "high",
    category: "system-execution",
    description: "Pipe de curl/wget a shell (curl | sh)",
    regex: /(curl|wget)[^|]+\|\s*(bash|sh|zsh)/,
    explanation:
      "El patrón más peligroso: descarga y ejecuta código sin verificación.",
  },
  {
    id: "spawn-suspicious",
    severity: "medium",
    category: "system-execution",
    description: "spawn() ejecutando bash/sh/powershell",
    regex: /spawn\s*\(\s*['"`](bash|sh|zsh|powershell|cmd)['"` ]/,
    explanation:
      "Lanza una shell directamente. Puede ejecutar comandos arbitrarios.",
  },
  {
    id: "reverse-shell",
    severity: "critical",
    category: "system-execution",
    description: "Patrón de reverse shell",
    regex: /(spawn|exec)\s*\([^)]*['"]\/(bin\/)?sh['"].*['"]-i['"]/,
    explanation:
      "Conexión reversible a una shell. Indicador claro de compromiso.",
  },
  {
    id: "cron-job-creation",
    severity: "high",
    category: "system-execution",
    description: "Creación de tareas programadas (cron)",
    regex: /(crontab|schedule|setInterval).*['"](.*\*.*){5}['"]/,
    explanation:
      "Intento de crear tareas programadas para ejecución persistente.",
  },
  // — OFUSCACIÓN —
  {
    id: "base64-decode-exec",
    severity: "high",
    category: "obfuscation",
    description: "Decodificación base64 seguida de ejecución",
    regex: /(Buffer\.from|atob)\s*\([^)]+,?\s*['"]base64['"]\s*\)\.toString/,
    explanation:
      "Decodifica un payload en base64. Técnica común para ocultar código malicioso.",
  },
  {
    id: "hex-string",
    severity: "low",
    category: "obfuscation",
    description: "String hexadecimal largo (posible payload ofuscado)",
    regex: /['"][0-9a-fA-F]{50,}['"]/,
    explanation:
      "String hexadecimal extenso. Puede ser un payload ofuscado o un hash legítimo.",
  },
  {
    id: "charcode-obfuscation",
    severity: "medium",
    category: "obfuscation",
    description: "Construcción de strings con fromCharCode",
    regex: /String\.fromCharCode\s*\(\s*\d+(\s*,\s*\d+){5,}\s*\)/,
    explanation:
      "Construye strings caracter por caracter para evadir detección.",
  },
  // — CREDENCIALES / KEYS —
  {
    id: "aws-keys-access",
    severity: "critical",
    category: "credentials",
    description: "Acceso a credenciales AWS",
    regex: /process\.env\.AWS_(SECRET|ACCESS|KEY)|AKIA[0-9A-Z]{16}/,
    explanation:
      "Acceso a claves de AWS. Permite acceso a recursos cloud.",
  },
  {
    id: "ci-env-vars",
    severity: "high",
    category: "credentials",
    description: "Acceso a variables de CI/CD",
    regex: /process\.env\.(CI_|GITHUB_|GITLAB_|CIRCLE_|TRAVIS_)/,
    explanation:
      "Acceso a tokens de CI/CD. Puede exponer credenciales de build.",
  },
  {
    id: "database-connection",
    severity: "medium",
    category: "credentials",
    description: "Conexión a base de datos",
    regex: /new\s+(require\(['"]pg['"]\)|require\(['"]mysql['"]\)|require\(['"]mongodb['"]\)|require\(['"]ioredis['"]\))/,
    explanation:
      "Conexión a base de datos. Puede ser legítima o intento de acceso no autorizado.",
  },
  // — CRYPTO / MINING —
  {
    id: "crypto-mining",
    severity: "medium",
    category: "malware",
    description: "Posible código de minería de criptomonedas",
    regex: /(setInterval|setTimeout).*(crypto|mining|pool|stratum)/,
    explanation:
      "Código relacionado con minería de criptomonedas. Puede usar recursos del sistema sin consentimiento.",
  },
  {
    id: "download-execute",
    severity: "critical",
    category: "malware",
    description: "Descarga y ejecución de código",
    regex: /https?\.get\(.*\)\.pipe\(.*exec\)|curl.*\|\s*(bash|sh|node)/,
    explanation:
      "Descarga contenido de internet y lo ejecuta inmediatamente.",
  },
];

export const lifecycleScriptPatterns = [
  {
    id: "lifecycle-network",
    severity: "high",
    category: "network",
    description: "Descarga de red en script de lifecycle",
    regex: /(curl|wget|fetch|http\.get|https\.get)/,
    explanation:
      "Script de lifecycle descarga contenido de internet. Puede instalar malware.",
  },
  {
    id: "lifecycle-exec",
    severity: "high",
    category: "system-execution",
    description: "Ejecución de comandos del sistema en lifecycle",
    regex: /(exec|execSync|spawn|child_process)/,
    explanation:
      "Script de lifecycle ejecuta comandos del sistema. Vector común en ataques.",
  },
  {
    id: "lifecycle-pipe-shell",
    severity: "high",
    category: "system-execution",
    description: "Pipe a shell en lifecycle",
    regex: /\|\s*(bash|sh|zsh|powershell)/,
    explanation: "El patrón más peligroso posible en un script de instalación.",
  },
  {
    id: "lifecycle-env-access",
    severity: "medium",
    category: "data-exfiltration",
    description: "Acceso a variables de entorno en lifecycle",
    regex: /process\.env\.[A-Z_]{3,}/,
    explanation:
      "Script de lifecycle accede a variables de entorno. Puede estar extrayendo keys.",
  },
];