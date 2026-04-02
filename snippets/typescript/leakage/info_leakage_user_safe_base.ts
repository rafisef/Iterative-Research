// INFORMATION LEAKAGE
// Controls exactly what data leaves the "server". Uses an explicit
// allowlist on user objects (not a blocklist) so new sensitive fields
// don't accidentally leak, and returns generic errors to the client
// while logging full details server-side.

interface InternalUser {
  id: string;
  email: string;
  passwordHash: string;
  mfaSecret: string;
  role: string;
}

function toPublicUser(user: InternalUser) {
  return { id: user.id, email: user.email, role: user.role };
}

function safeError(publicMsg: string, internalErr?: Error) {
  if (internalErr) console.error("[INTERNAL]", internalErr.stack);
  return { status: "error", message: publicMsg };
}
