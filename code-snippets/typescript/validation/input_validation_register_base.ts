// INPUT VALIDATION
// Validates and sanitizes user input before it touches anything.
// Uses a schema to enforce types, lengths, and formats upfront
// so garbage never makes it past the front door.

import { z } from "zod";

const UserSchema = z.object({
  username: z.string().min(3).max(30).regex(/^[a-zA-Z0-9_]+$/),
  email: z.string().email(),
  age: z.number().int().min(13).max(120),
});

function registerUser(input: unknown) {
  return UserSchema.parse(input);
}
