import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isPublicAddress, isSafeUrl } from "./safe-url.js";

/** Resolve once, reject all private results, and pin the connection to that resolution. */
export async function safeFetch(value: string, init: RequestInit = {}, redirects = 0): Promise<Response> {
  if (!isSafeUrl(value)) throw new Error("Unsafe remote URL");
  const url = new URL(value);
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  const addresses = isIP(hostname)
    ? [{ address: hostname, family: isIP(hostname) }]
    : await lookup(hostname, { all: true });
  if (!addresses.length || addresses.some(({ address }) => !isPublicAddress(address))) {
    throw new Error("Remote hostname resolves to a non-public address");
  }
  const pinned = addresses[0];
  const headers: Record<string, string> = {};
  new Headers(init.headers).forEach((value, key) => { headers[key] = value; });
  if (headers.host) throw new Error("Sensitive headers are not allowed");
  if (init.body != null && typeof init.body !== "string") throw new Error("Unsupported remote request body");
  const response = await new Promise<Response>((resolve, reject) => {
    const request = (url.protocol === "https:" ? httpsRequest : httpRequest)(url, {
      method: init.method || "GET",
      headers,
      agent: false,
      signal: init.signal || AbortSignal.timeout(10_000),
      lookup: (_host, options, callback) => {
        if (options.all) callback(null, [{ address: pinned.address, family: pinned.family }]);
        else callback(null, pinned.address, pinned.family);
      },
    }, incoming => {
      const chunks: Buffer[] = [];
      let size = 0;
      incoming.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > 5 * 1024 * 1024) {
          incoming.destroy(new Error("Remote response exceeds 5MB"));
          return;
        }
        chunks.push(chunk);
      });
      incoming.on("error", reject);
      incoming.on("end", () => {
        const responseHeaders = new Headers();
        for (const [name, header] of Object.entries(incoming.headers)) {
          if (header !== undefined) responseHeaders.set(name, Array.isArray(header) ? header.join(", ") : header);
        }
        const status = incoming.statusCode || 502;
        resolve(new Response([204, 205, 304].includes(status) ? null : Buffer.concat(chunks), { status, headers: responseHeaders }));
      });
    });
    request.on("error", reject);
    request.end(init.body ?? undefined);
  });
  if ([301, 302, 303, 307, 308].includes(response.status)) {
    if (init.redirect === "error" || (init.method && init.method !== "GET")) throw new Error("Remote redirects are not allowed");
    if (init.redirect === "manual") return response;
    if (redirects >= 3) throw new Error("Too many remote redirects");
    const location = response.headers.get("location");
    if (!location) throw new Error("Redirect missing Location");
    return safeFetch(new URL(location, url).href, init, redirects + 1);
  }
  return response;
}
