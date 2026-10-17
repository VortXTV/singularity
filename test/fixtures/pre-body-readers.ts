// Test-only exact pre-body reader functions from c5f608b0d13eddf17d4956f2b77eba8b184d5728.
// Only export prefixes were added. Never import this vulnerable baseline from production.
export async function readJSON(req: Request, maxBytes = 1024 * 1024): Promise<Record<string, unknown> | null> {
  // Enforce the cap on the ACTUAL body, not a possibly-absent or lying Content-Length header.
  let text: string;
  try {
    text = await req.text();
  } catch {
    return null;
  }
  if (text.length > maxBytes) return null;
  try {
    const b = JSON.parse(text);
    return b && typeof b === "object" ? (b as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export async function readCappedText(res: Response, cap: number): Promise<string | null> {
  const declared = Number(res.headers.get("content-length") ?? "");
  if (Number.isFinite(declared) && declared > cap) return null; // cheap early-out; not sufficient alone
  if (!res.body) return null;
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let total = 0;
  let out = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > cap) return null; // stop pulling: the bomb never gets fully buffered
      out += decoder.decode(value, { stream: true });
    }
    return out + decoder.decode();
  } catch {
    return null;
  } finally {
    await reader.cancel().catch(() => {});
  }
}
