import { useEffect, useState } from "react";
import { format } from "date-fns";
import { Badge } from "@/components/ui/badge";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

interface Commit {
  sha: string;
  scope: string;
  message: string;
  timestamp: string;
}

interface ChangelogData {
  limit: number;
  total_count: number;
  commits: Commit[];
  scopes: Record<string, number>;
}

const SCOPE_COLORS: Record<string, string> = {
  feat: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
  fix: "bg-blue-500/20 text-blue-300 border-blue-500/40",
  perf: "bg-purple-500/20 text-purple-300 border-purple-500/40",
  ui: "bg-pink-500/20 text-pink-300 border-pink-500/40",
  qa: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  refactor: "bg-indigo-500/20 text-indigo-300 border-indigo-500/40",
  docs: "bg-slate-500/20 text-slate-300 border-slate-500/40",
  chore: "bg-gray-500/20 text-gray-300 border-gray-500/40",
  style: "bg-cyan-500/20 text-cyan-300 border-cyan-500/40",
  test: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
  other: "bg-slate-700/40 text-slate-300 border-slate-600/40",
};

export default function ChangelogPage() {
  const [data, setData] = useState<ChangelogData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchChangelog = async () => {
      try {
        const response = await fetch("/api/v1/changelog/recent?limit=50");
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        const json = await response.json();
        setData(json);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to fetch changelog");
      } finally {
        setLoading(false);
      }
    };

    fetchChangelog();
  }, []);

  if (loading) {
    return <PageSkeleton />;
  }

  if (error) {
    return (
      <div className="min-h-screen bg-slate-950 px-6 py-12">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-3xl font-bold text-slate-50 mb-4">Changelog</h1>
          <div className="bg-red-950/30 border border-red-700/40 rounded-lg p-6 text-red-300">
            Error loading changelog: {error}
          </div>
        </div>
      </div>
    );
  }

  if (!data || data.commits.length === 0) {
    return (
      <div className="min-h-screen bg-slate-950 px-6 py-12">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-3xl font-bold text-slate-50 mb-4">Changelog</h1>
          <div className="bg-slate-900/50 border border-slate-700/40 rounded-lg p-6 text-slate-400">
            No commits found.
          </div>
        </div>
      </div>
    );
  }

  // Sort commits by scope for grouped display
  const grouped: Record<string, Commit[]> = {};
  data.commits.forEach((commit) => {
    if (!grouped[commit.scope]) {
      grouped[commit.scope] = [];
    }
    grouped[commit.scope].push(commit);
  });

  // Sort scopes by count (descending)
  const sortedScopes = Object.entries(grouped).sort((a, b) => b[1].length - a[1].length);

  return (
    <div className="min-h-screen bg-slate-950 px-6 py-12">
      <div className="max-w-4xl mx-auto">
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-slate-50 mb-2">ALDECI Changelog</h1>
          <p className="text-slate-400">
            Latest {data.limit} commits across {Object.keys(data.scopes).length} scopes
            {data.total_count > data.limit && ` (${data.total_count} total)`}
          </p>
        </div>

        {/* Scope summary */}
        <div className="mb-8 p-4 bg-slate-900/50 rounded-lg border border-slate-700/40">
          <h2 className="text-sm font-semibold text-slate-300 mb-3 uppercase tracking-wider">
            Changes by Type
          </h2>
          <div className="flex flex-wrap gap-2">
            {sortedScopes.map(([scope, commits]) => (
              <div key={scope} className="flex items-center gap-2">
                <Badge variant="outline" className={`${SCOPE_COLORS[scope]} border`}>
                  {scope}
                </Badge>
                <span className="text-xs text-slate-400">{commits.length}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Commits grouped by scope */}
        <div className="space-y-8">
          {sortedScopes.map(([scope, commits]) => (
            <div key={scope}>
              <h2 className="text-lg font-semibold text-slate-50 mb-4 pb-2 border-b border-slate-700/40">
                <Badge variant="outline" className={`${SCOPE_COLORS[scope]} border mr-3`}>
                  {scope}
                </Badge>
                <span className="text-slate-400">({commits.length})</span>
              </h2>

              <div className="space-y-3">
                {commits.map((commit) => (
                  <div
                    key={commit.sha}
                    className="p-4 bg-slate-900/40 rounded-lg border border-slate-700/20 hover:border-slate-600/40 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <code className="text-xs font-mono text-slate-500 bg-slate-800/60 px-2 py-1 rounded">
                            {commit.sha}
                          </code>
                          <span className="text-xs text-slate-500">
                            {format(new Date(commit.timestamp), "MMM d, yyyy HH:mm")}
                          </span>
                        </div>
                        <p className="text-slate-200 break-words">{commit.message}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="mt-12 pt-6 border-t border-slate-700/40 text-center text-slate-500 text-sm">
          <p>
            ALDECI Beast Mode — Open source security intelligence platform
          </p>
          <p className="mt-2">
            View full history:{" "}
            <a
              href="https://github.com/DevOpsMadDog/Fixops"
              target="_blank"
              rel="noopener noreferrer"
              className="text-indigo-400 hover:text-indigo-300"
            >
              github.com/DevOpsMadDog/Fixops
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}
