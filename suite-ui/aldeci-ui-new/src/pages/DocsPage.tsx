/**
 * DocsPage — Public documentation hub (/docs/*)
 * Renders legal, installation, and POC playbook docs via react-markdown
 * Routes: /docs/tos, /docs/privacy, /docs/dpa, /docs/install, /docs/poc
 * All markdown loaded via Vite raw imports (zero runtime fetch)
 */

import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import {
  BookOpen,
  FileText,
  Shield,
  Zap,
  Download,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ── Raw Markdown Imports (Vite) ────────────────────────────────────────────

// @ts-ignore — Vite raw import
import tosRaw from "@/assets/docs/legal/TOS.md?raw";
// @ts-ignore — Vite raw import
import privacyRaw from "@/assets/docs/legal/PRIVACY.md?raw";
// @ts-ignore — Vite raw import
import dpaRaw from "@/assets/docs/legal/DPA.md?raw";
// @ts-ignore — Vite raw import
import installRaw from "@/assets/docs/INSTALL.md?raw";
// @ts-ignore — Vite raw import
import pocRaw from "@/assets/docs/sales/POC_PLAYBOOK.md?raw";

// ── Types ──────────────────────────────────────────────────────────────────

interface DocMetadata {
  id: string;
  title: string;
  description: string;
  icon: React.ReactNode;
  color: string;
  route: string;
  content: string;
}

// ── Doc Registry ───────────────────────────────────────────────────────────

const DOCS: Record<string, DocMetadata> = {
  tos: {
    id: "tos",
    title: "Terms of Service",
    description: "Legal terms governing ALDECI platform use",
    icon: <FileText className="w-5 h-5" />,
    color: "from-blue-600 to-blue-400",
    route: "/docs/tos",
    content: tosRaw,
  },
  privacy: {
    id: "privacy",
    title: "Privacy Policy",
    description: "How we collect, use, and protect your data",
    icon: <Shield className="w-5 h-5" />,
    color: "from-indigo-600 to-indigo-400",
    route: "/docs/privacy",
    content: privacyRaw,
  },
  dpa: {
    id: "dpa",
    title: "Data Processing Agreement",
    description: "GDPR/CCPA data processor terms",
    icon: <FileText className="w-5 h-5" />,
    color: "from-purple-600 to-purple-400",
    route: "/docs/dpa",
    content: dpaRaw,
  },
  install: {
    id: "install",
    title: "Installation Guide",
    description: "Self-hosted deployment instructions",
    icon: <Zap className="w-5 h-5" />,
    color: "from-emerald-600 to-emerald-400",
    route: "/docs/install",
    content: installRaw,
  },
  poc: {
    id: "poc",
    title: "POC Playbook",
    description: "Proof-of-concept testing and validation flow",
    icon: <BookOpen className="w-5 h-5" />,
    color: "from-orange-600 to-orange-400",
    route: "/docs/poc",
    content: pocRaw,
  },
};

// ── Markdown Renderer ──────────────────────────────────────────────────────

const markdownComponents = {
  h1: ({ ...props }: any) => (
    <h1 className="text-4xl font-bold text-slate-50 mt-8 mb-6" {...props} />
  ),
  h2: ({ ...props }: any) => (
    <h2 className="text-3xl font-bold text-slate-100 mt-8 mb-4 border-b border-slate-700 pb-3" {...props} />
  ),
  h3: ({ ...props }: any) => (
    <h3 className="text-2xl font-semibold text-slate-200 mt-6 mb-3" {...props} />
  ),
  p: ({ ...props }: any) => (
    <p className="text-slate-300 leading-relaxed mb-4" {...props} />
  ),
  ul: ({ ...props }: any) => (
    <ul className="list-disc list-inside text-slate-300 space-y-2 ml-4 mb-4" {...props} />
  ),
  ol: ({ ...props }: any) => (
    <ol className="list-decimal list-inside text-slate-300 space-y-2 ml-4 mb-4" {...props} />
  ),
  li: ({ ...props }: any) => (
    <li className="text-slate-300" {...props} />
  ),
  blockquote: ({ ...props }: any) => (
    <blockquote
      className="border-l-4 border-indigo-500 bg-slate-800 rounded px-4 py-3 my-4 text-slate-300 italic"
      {...props}
    />
  ),
  code: ({ ...props }: any) => (
    <code
      className="bg-slate-800 text-emerald-300 px-2 py-1 rounded text-sm font-mono"
      {...props}
    />
  ),
  pre: ({ ...props }: any) => (
    <pre
      className="bg-slate-900 text-emerald-300 p-4 rounded-lg overflow-x-auto mb-4 border border-slate-700"
      {...props}
    />
  ),
  table: ({ ...props }: any) => (
    <table
      className="w-full border-collapse text-slate-300 my-4 border border-slate-700"
      {...props}
    />
  ),
  thead: ({ ...props }: any) => (
    <thead className="bg-slate-800 border-b border-slate-700" {...props} />
  ),
  th: ({ ...props }: any) => (
    <th className="px-4 py-2 text-left font-semibold text-slate-100" {...props} />
  ),
  td: ({ ...props }: any) => (
    <td className="px-4 py-2 border-b border-slate-700" {...props} />
  ),
  a: ({ ...props }: any) => (
    <a
      className="text-indigo-400 hover:text-indigo-300 underline"
      {...props}
    />
  ),
};

// ── Main Component ─────────────────────────────────────────────────────────

export default function DocsPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const [currentDoc, setCurrentDoc] = useState<DocMetadata | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    // Extract doc ID from path: /docs/{id}
    const pathParts = location.pathname.split("/");
    const docId = pathParts[pathParts.length - 1] || "tos";
    const doc = DOCS[docId];

    if (doc) {
      setCurrentDoc(doc);
    } else {
      setCurrentDoc(DOCS.tos);
      navigate("/docs/tos");
    }
  }, [location, navigate]);

  const handleDownload = () => {
    if (!currentDoc) return;
    const element = document.createElement("a");
    const file = new Blob([currentDoc.content], { type: "text/markdown" });
    element.href = URL.createObjectURL(file);
    element.download = `${currentDoc.id}.md`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const handleCopy = () => {
    if (!currentDoc) return;
    navigator.clipboard.writeText(currentDoc.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!currentDoc) {
    return (
      <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-950 flex items-center justify-center">
        <div className="text-slate-400">Loading documentation...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-950">
      {/* Header */}
      <div className="bg-slate-900/50 border-b border-slate-700 sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-6 py-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <BookOpen className="w-8 h-8 text-indigo-400" />
            <h1 className="text-2xl font-bold text-slate-50">Documentation</h1>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleCopy}
              className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition-colors"
            >
              {copied ? "Copied!" : "Copy"}
            </button>
            <button
              onClick={handleDownload}
              className="px-3 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium transition-colors flex items-center gap-2"
            >
              <Download className="w-4 h-4" />
              Download
            </button>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Sidebar Navigation */}
          <div className="lg:col-span-1">
            <div className="space-y-2 sticky top-24">
              {Object.values(DOCS).map((doc) => (
                <button
                  key={doc.id}
                  onClick={() => navigate(doc.route)}
                  className={cn(
                    "w-full px-4 py-3 rounded-lg text-left transition-all font-medium text-sm flex items-center justify-between group",
                    currentDoc.id === doc.id
                      ? "bg-indigo-600 text-white shadow-lg"
                      : "bg-slate-800/50 text-slate-300 hover:bg-slate-700/70"
                  )}
                >
                  <span className="flex items-center gap-2">
                    <span className="text-base">{doc.icon}</span>
                    {doc.title}
                  </span>
                  {currentDoc.id === doc.id && (
                    <ChevronRight className="w-4 h-4" />
                  )}
                </button>
              ))}
            </div>
          </div>

          {/* Main Content */}
          <div className="lg:col-span-3">
            {/* Doc Header Card */}
            <div
              className={cn(
                "bg-gradient-to-r rounded-lg p-8 mb-8 text-white shadow-lg",
                `${currentDoc.color}`
              )}
            >
              <div className="flex items-start gap-4">
                <div className="text-4xl">{currentDoc.icon}</div>
                <div>
                  <h2 className="text-3xl font-bold mb-2">
                    {currentDoc.title}
                  </h2>
                  <p className="text-white/90">{currentDoc.description}</p>
                </div>
              </div>
            </div>

            {/* Markdown Content */}
            <div className="bg-slate-800/30 rounded-lg p-8 border border-slate-700/50">
              <article className="prose prose-invert max-w-none">
                <ReactMarkdown components={markdownComponents}>
                  {currentDoc.content}
                </ReactMarkdown>
              </article>
            </div>

            {/* Footer Navigation */}
            <div className="mt-12 flex justify-between items-center">
              <button
                onClick={() => {
                  const docIds = Object.keys(DOCS);
                  const currentIdx = docIds.indexOf(currentDoc.id);
                  const prevIdx = (currentIdx - 1 + docIds.length) % docIds.length;
                  navigate(DOCS[docIds[prevIdx]].route);
                }}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition-colors"
              >
                ← Previous
              </button>
              <span className="text-slate-400 text-sm">
                {Object.keys(DOCS).indexOf(currentDoc.id) + 1} of{" "}
                {Object.keys(DOCS).length}
              </span>
              <button
                onClick={() => {
                  const docIds = Object.keys(DOCS);
                  const currentIdx = docIds.indexOf(currentDoc.id);
                  const nextIdx = (currentIdx + 1) % docIds.length;
                  navigate(DOCS[docIds[nextIdx]].route);
                }}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition-colors"
              >
                Next →
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
