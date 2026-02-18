export function encodePlaygroundState(expr: string, yaml: string): string {
  const bytes = new TextEncoder().encode(JSON.stringify({ e: expr, c: yaml }));
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary);
}

export function decodePlaygroundState(
  hash: string,
): { expression: string; context: string } | null {
  try {
    const binary = atob(hash);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const data = JSON.parse(new TextDecoder().decode(bytes));
    if (typeof data.e === "string" && typeof data.c === "string") {
      return { expression: data.e, context: data.c };
    }
  } catch {
    // ignore malformed hash
  }
  return null;
}
