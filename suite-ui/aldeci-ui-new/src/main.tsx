import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "sonner";
import App from "./App";
import Console from "./console/Console";
import { AuthProvider } from "@/lib/auth";
import "./styles/globals.css";

/**
 * The console is the product's face. The previous surface (~300 pages, one per
 * engine) is still mounted behind VITE_LEGACY_UI=1 — the same pattern
 * FIXOPS_CORE_MODE uses on the API side, where fixing one loose prefix match
 * took the advertised surface from 455 paths to 308 without deleting anything.
 *
 * Reversible on purpose. Twice this month something that looked dead turned out
 * to be load-bearing: evidence-chain was a fully built chain-of-custody engine
 * that nothing fed, and five "product" test failures were the tests being wrong.
 * A flag survives that kind of mistake; `git rm` under time pressure does not.
 */
const USE_LEGACY_UI = import.meta.env.VITE_LEGACY_UI === "1";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          {/* No login gate. The API key comes from configuration — an auth wall
              between an operator and their own console buys nothing here and
              costs a step. Real authorization stays in the API, where it is
              enforced rather than merely displayed. */}
          {USE_LEGACY_UI ? <App /> : <Console />}
        </AuthProvider>
        <Toaster
          position="bottom-right"
          theme="dark"
          richColors
          closeButton
          toastOptions={{
            style: {
              fontFamily: "var(--font-sans)",
            },
          }}
        />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>
);
