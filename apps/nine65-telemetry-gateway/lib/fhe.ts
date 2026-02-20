import { config } from "@/lib/config";

async function withTimeout(url: string, init: RequestInit, timeoutMs: number) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
      cache: "no-store"
    });
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchFhe(path: string, init: RequestInit = {}) {
  const url = `${config.fheServiceUrl}${path}`;
  return withTimeout(url, init, 5000);
}

export async function fetchFheJson<T>(
  path: string,
  init: RequestInit = {}
): Promise<T> {
  const response = await fetchFhe(path, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(init.headers ?? {})
    }
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`FHE upstream error ${response.status}: ${text}`);
  }

  return (await response.json()) as T;
}
