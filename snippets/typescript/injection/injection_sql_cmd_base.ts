// INJECTION VULNERABILITIES
// SQL uses parameterized queries so values are never interpolated.
// Command execution uses execFileSync (no shell) with an allowlist of commands.
// User input never touches a command string.

// SQL — parameterized query, value never touches the query string
async function findUser(pool: any, email: string) {
  const result = await pool.query(
    "SELECT id, email, role FROM users WHERE email = $1",
    [email]
  );
  return result.rows[0];
}

// Commands — allowlist only, execFileSync skips the shell entirely
function runCommand(name: string): string {
  const ALLOWED: Record<string, string[]> = {
    diskUsage: ["df", "-h"],
    uptime: ["uptime"],
    whoami: ["whoami"],
  };

  const cmd = ALLOWED[name];
  if (!cmd) throw new Error(`Command not allowed: ${name}`);

  const { execFileSync } = require("child_process");
  return execFileSync(cmd[0], cmd.slice(1), { encoding: "utf-8" });
}
