import { useEffect, useState } from "react";
import { Card } from "@/components/ui/card";
import { AlertCircle, Zap } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";

export default function ApiReferencePage() {
  const [swaggerLoaded, setSwaggerLoaded] = useState(false);
  const [useIframe, setUseIframe] = useState(false);

  useEffect(() => {
    // Try to load swagger-ui CSS if available, else use iframe fallback
    const checkSwagger = async () => {
      try {
        // Attempt to load swagger-ui assets from CDN
        const link = document.createElement("link");
        link.rel = "stylesheet";
        link.href =
          "https://cdn.jsdelivr.net/npm/swagger-ui-dist@4/swagger-ui.css";
        document.head.appendChild(link);
        setSwaggerLoaded(true);
      } catch {
        // If CDN fails, use iframe fallback to FastAPI /docs
        setUseIframe(true);
      }
    };

    checkSwagger();
  }, []);

  // Iframe fallback — loads FastAPI's built-in OpenAPI UI
  if (useIframe) {
    return (
      <div className="min-h-screen w-full bg-slate-950 p-4">
        <div className="mx-auto max-w-7xl space-y-4">
          <div className="flex items-center gap-2">
            <Zap className="h-5 w-5 text-amber-500" />
            <h1 className="text-2xl font-semibold text-slate-50">API Reference</h1>
          </div>
          <Alert className="border-amber-700 bg-amber-950/30">
            <AlertCircle className="h-4 w-4 text-amber-500" />
            <AlertDescription className="text-amber-200">
              Swagger UI library not loaded. Using FastAPI built-in documentation instead.
            </AlertDescription>
          </Alert>
          <Card className="border-slate-700 bg-slate-900">
            <iframe
              src="/docs"
              title="API Reference — FastAPI Docs"
              className="h-[calc(100vh-200px)] w-full border-0"
            />
          </Card>
        </div>
      </div>
    );
  }

  // Swagger UI loaded — use direct OpenAPI spec
  return (
    <div className="min-h-screen w-full bg-slate-950 p-4">
      <div className="mx-auto max-w-7xl space-y-4">
        <div className="flex items-center gap-2">
          <Zap className="h-5 w-5 text-indigo-500" />
          <h1 className="text-2xl font-semibold text-slate-50">API Reference</h1>
        </div>
        <Card className="border-slate-700 bg-slate-900">
          <div
            id="swagger-ui"
            className="[&_.swagger-ui]:bg-transparent [&_.swagger-ui_*]:color-inherit"
          />
        </Card>
      </div>

      <script
        src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@4/swagger-ui-bundle.js"
        onLoad={() => {
          if (window.SwaggerUIBundle) {
            window.SwaggerUIBundle({
              url: "/openapi.json",
              dom_id: "#swagger-ui",
              presets: [
                window.SwaggerUIBundle.presets.apis,
                window.SwaggerUIBundle.SwaggerUIStandalonePreset,
              ],
              layout: "BaseLayout",
              theme: "dark",
            });
          }
        }}
      />
    </div>
  );
}
