export function badAssert(value: number): number {
  console.assert(value > 0, "must be positive");
  return value;
}

export function factorial(n: number): number {
  if (n <= 1) return 1;
  return n * factorial(n - 1);
}

export function spinForever(items: number[]): void {
  while (true) {
    if (items.length === 0) break;
    items.pop();
  }
}

export function deepBranches(a: boolean, b: boolean, c: boolean, d: boolean): number {
  if (a) {
    if (b) {
      if (c) {
        if (d) {
          if (a && c) return 1;
        }
      }
    }
  }
  return 0;
}

export function wideSignature(a: number, b: number, c: number, d: number, e: number): number {
  return a + b + c + d + e;
}

export function invertedNames(timeout: number, start: number, finish: number): number {
  const maxLatencyMs = timeout;
  const usrAcct = start + finish;
  return maxLatencyMs + usrAcct;
}

export async function implicitFetch(url: string): Promise<Response> {
  return fetch(url);
}
