# Frontend CSRF Handling

This interceptor sketch shows how to react to CSRF errors from the API. It inspects the structured `code` and the `Retry-After` header exposed by the backend.

```ts
// axios-csrf-interceptor.ts
import axios, { AxiosError, type AxiosInstance } from "axios";

const api: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL,
});

let isRefreshing = false;
let pendingQueue: Array<() => void> = [];

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function fetchCsrfToken(): Promise<string> {
  const { data } = await api.get("/auth/csrf-token", { withCredentials: true });
  // Backend sets cookie; return for convenience
  return data?.data?.csrfToken;
}

async function refreshCsrfAndRetry(error: AxiosError) {
  if (isRefreshing) {
    await new Promise<void>((resolve) => pendingQueue.push(resolve));
  }

  isRefreshing = true;
  try {
    await fetchCsrfToken();
    pendingQueue.forEach((resolve) => resolve());
    pendingQueue = [];
    if (error.config) {
      return api.request(error.config);
    }
    throw error;
  } finally {
    isRefreshing = false;
  }
}

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const code = (error.response?.data as { code?: string } | undefined)?.code;
    const retryAfterHeader = error.response?.headers?.["retry-after"];
    const retryAfterMs = retryAfterHeader
      ? Number(retryAfterHeader) * 1000
      : undefined;

    if (code === "CSRF_BLOCKED") {
      if (retryAfterMs && retryAfterMs > 0) {
        await wait(retryAfterMs);
      }
      return refreshCsrfAndRetry(error);
    }

    if (code === "errors.csrf.invalid") {
      // Token mismatch/missing-store: fetch a fresh token and retry once
      return refreshCsrfAndRetry(error);
    }

    return Promise.reject(error);
  }
);

export default api;
```

Notes:

- The backend sends `code: CSRF_BLOCKED`, a `Retry-After` header (seconds), and `details.retryAfterSeconds`; the header is used here for backoff.
- `errors.csrf.invalid` is also handled by fetching a new token then retrying once.
- `pendingQueue` prevents multiple concurrent retries while a refresh is in flight.
- Always enable `withCredentials: true` on requests so cookies flow.
- For production, add max-retry guards/metrics and surface UI feedback when a block occurs.
