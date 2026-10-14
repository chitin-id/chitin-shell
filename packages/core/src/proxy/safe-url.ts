/** Syntactic URL validation. Server fetches must also validate and pin DNS. */
export function isPublicAddress(address: string): boolean {
  const ip = address.toLowerCase().replace(/^\[|\]$/g, "");
  if (ip.includes(":")) {
    return /^[23][0-9a-f]{0,3}:/.test(ip)
      && !/^2002:/.test(ip)
      && !/^2001:(?:0{1,4}|db8|0?1[0-9a-f])(?::|$)/.test(ip);
  }
  const parts = ip.split(".");
  if (parts.length !== 4 || parts.some(part => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return false;
  const [a, b, c] = parts.map(Number);
  return a !== 0 && a !== 10 && a !== 127 && a < 224
    && !(a === 100 && b >= 64 && b <= 127)
    && !(a === 169 && b === 254)
    && !(a === 172 && b >= 16 && b <= 31)
    && !(a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99)))
    && !(a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100)))
    && !(a === 203 && b === 0 && c === 113);
}

export function isSafeUrl(value: string): boolean {
  try {
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) return false;
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
    if (host.includes(":") || /^[\d.]+$/.test(host)) return isPublicAddress(host);
    return host.includes(".") && !/(?:^|\.)(?:localhost|local|internal|test|invalid)$/.test(host)
      && !["metadata.google", "instance-data", "kubernetes.default"].includes(host);
  } catch {
    return false;
  }
}
