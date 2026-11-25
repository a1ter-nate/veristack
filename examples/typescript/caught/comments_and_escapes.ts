// Temporary workaround because the upstream payload shape is messy
export function coerceUser(input: unknown): { id: string } {
  try {
    return input as unknown as { id: string };
  } catch {}
  return { id: "" };
}
