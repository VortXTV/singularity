/** Internal bounded body readers. No route, signature or JSON projection policy lives here. */
const BODY_READ_TIMEOUT_MS = 8000;
const JSON_MAX_CHARS = 1024 * 1024;
export interface BodyReadOptions { signal?: AbortSignal; timeoutMs?: number; deadlineAt?: number; }
interface TextLimits extends BodyReadOptions {
  maxBytes: number;
  maxChars?: number;
  declaredLength?: string | null;
  nativeRequestText?: boolean;
}

async function readText(body: ReadableStream<Uint8Array> | null, limits: TextLimits): Promise<string | null> {
  const started = performance.now();
  if (!body) return null;
  let reader: ReadableStreamDefaultReader<Uint8Array>;
  try { reader = body.getReader(); } catch { return null; }
  const requested = limits.timeoutMs ?? BODY_READ_TIMEOUT_MS;
  const timeout = Number.isFinite(requested) && requested >= 0
    ? Math.min(requested, BODY_READ_TIMEOUT_MS) : BODY_READ_TIMEOUT_MS;
  // Outbound origin is captured before fetch; a pending abort callback must not grant a fresh budget.
  const invalidOrigin = limits.deadlineAt !== undefined && !Number.isFinite(limits.deadlineAt);
  const deadline = invalidOrigin ? started : Math.min(started + timeout, limits.deadlineAt ?? Infinity);
  let stopped = false;
  let ended = false;
  let forwardedController: ReadableStreamDefaultController<Uint8Array> | undefined;
  const errorForwarded = () => {
    try { forwardedController?.error(new Error("Request body admission stopped")); } catch {}
  };
  let stop!: () => void;
  const stopResult = new Promise<null>((resolve) => {
    stop = () => {
      if (stopped) return;
      stopped = true;
      errorForwarded();
      resolve(null);
    };
  });
  const onAbort = () => stop();
  limits.signal?.addEventListener("abort", onAbort, { once: true });
  if (limits.signal?.aborted) stop();
  const timer = setTimeout(stop, Math.max(0, deadline - performance.now()));
  const consume = async (): Promise<string | null> => {
    // Preserve the existing outbound Content-Length early rejection. Requests do not supply this.
    const declared = Number(limits.declaredLength ?? "");
    if (limits.declaredLength !== undefined && Number.isFinite(declared) && declared > limits.maxBytes) return null;
    if (limits.nativeRequestText) {
      if (stopped || performance.now() >= deadline) return null;
      let bytes = 0;
      const forwarded = new ReadableStream<Uint8Array>({
        start(controller) {
          forwardedController = controller;
          if (stopped) errorForwarded();
        },
        async pull(controller) {
          if (stopped || performance.now() >= deadline) { stop(); return; }
          try {
            const { done, value } = await reader.read();
            if (stopped || performance.now() >= deadline) { stop(); return; }
            if (done) { ended = true; controller.close(); return; }
            if (value.byteLength > limits.maxBytes - bytes) { stop(); return; }
            bytes += value.byteLength;
            // Preserve boundaries and empty chunks; never retain a mutable source view.
            const copy = new Uint8Array(value.byteLength);
            copy.set(value);
            if (stopped || performance.now() >= deadline) { stop(); return; }
            controller.enqueue(copy);
          } catch { stop(); }
        },
        // The shared finally owns original cancellation exactly once, without awaiting it.
        cancel() { stop(); },
      }, { highWaterMark: 0 });
      // Node requires duplex for a stream body; workerd receives the same finite byte guard.
      const init = { method: "POST", body: forwarded, duplex: "half" as const };
      const text = await new Request("https://body.invalid/", init).text();
      if (stopped || performance.now() >= deadline) return null;
      return limits.maxChars !== undefined && text.length > limits.maxChars ? null : text;
    }
    const decoder = new TextDecoder(); // nonfatal UTF-8, including streaming leading-BOM handling
    let bytes = 0;
    let text = "";
    for (;;) {
      if (stopped || performance.now() >= deadline) return null;
      const { done, value } = await reader.read();
      if (stopped || performance.now() >= deadline) return null;
      if (done) { ended = true; break; }
      bytes += value.byteLength;
      if (bytes > limits.maxBytes) return null;
      text += decoder.decode(value, { stream: true });
      if (limits.maxChars !== undefined && text.length > limits.maxChars) return null;
    }
    text += decoder.decode();
    if (limits.maxChars !== undefined && text.length > limits.maxChars) return null;
    return performance.now() >= deadline ? null : text;
  };
  try {
    // One race for the complete consume task, not one retained stop callback per chunk.
    return await Promise.race([consume(), stopResult]);
  } catch {
    return null;
  } finally {
    stopped = true;
    errorForwarded();
    clearTimeout(timer);
    limits.signal?.removeEventListener("abort", onAbort);
    if (!ended) {
      // Cancel is best-effort ownership cleanup, never an additional unbounded awaited phase.
      try { void reader.cancel().catch(() => {}); } catch {}
    }
    try { reader.releaseLock(); } catch {}
  }
}

/** Legacy decoded UTF-16 cap; request cancellation belongs only to req.signal. */
export async function readRequestJSON(
  req: Request, maxChars = JSON_MAX_CHARS, options: Pick<BodyReadOptions, "timeoutMs"> = {},
): Promise<Record<string, unknown> | null> {
  // Compatibility requires at most two omitted leading BOMs; native runtime gates must verify it.
  // Three bytes per decoded UTF-16 unit plus those six bytes bounds native input accumulation.
  // Native Request.text, including chunk-sensitive BOM policy, owns the authoritative char cap.
  const text = await readText(req.body, {
    maxBytes: 3 * maxChars + 6, maxChars, nativeRequestText: true,
    timeoutMs: options.timeoutMs, signal: req.signal,
  });
  if (text === null) return null;
  try {
    const value = JSON.parse(text);
    return value && typeof value === "object" ? value as Record<string, unknown> : null;
  } catch { return null; }
}

/** Actual delivered/decompressed bytes; keep existing response-header and UTF-8 policies. */
export async function readCappedText(
  res: Response, cap: number, options: BodyReadOptions = {},
): Promise<string | null> {
  return readText(res.body, {
    maxBytes: cap, declaredLength: res.headers.get("content-length"),
    signal: options.signal, timeoutMs: options.timeoutMs, deadlineAt: options.deadlineAt,
  });
}
