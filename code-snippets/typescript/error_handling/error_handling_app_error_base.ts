// ERROR HANDLING
// Separates expected errors (bad input, not found) from unexpected
// ones (something actually broke). Expected errors return clean
// messages to the client. Unexpected errors get logged in full
// but the client only sees a generic 500 — no stack traces leak out.

class AppError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number = 500
  ) {
    super(message);
  }
}

function handleError(err: unknown): { statusCode: number; body: object } {
  if (err instanceof AppError) {
    return { statusCode: err.statusCode, body: { error: err.message } };
  }

  console.error("[UNHANDLED]", err);
  return { statusCode: 500, body: { error: "An unexpected error occurred" } };
}
