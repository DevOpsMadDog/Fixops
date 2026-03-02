import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Brain,
  Search,
  AlertTriangle,
  Shield,
  TrendingUp,
  ExternalLink,
  ChevronDown,
  RefreshCw,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { ScrollArea } from '../components/ui/scroll-area';
import { Progress } from '../components/ui/progress';
import { feedsApi } from '../lib/api';
import { toast } from 'sonner';

interface VulnerabilityCardProps {
  cve: string;
  title?: string;
  severity: string;
  epss?: number;
  cvss?: number;
  inKev?: boolean;
  description?: string;
}

function VulnerabilityCard({ cve, title, severity, epss, cvss, inKev, description }: VulnerabilityCardProps) {
  const [expanded, setExpanded] = useState(false);

  const severityVariant = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
    info: 'info',
  }[severity.toLowerCase()] as 'critical' | 'high' | 'medium' | 'low' | 'info';

  return (
    <motion.div
      layout
      className="p-4 rounded-lg border border-border bg-muted/30 hover:border-primary/30 transition-colors"
    >
      <div className="flex items-start justify-between">
        <div className="space-y-1 flex-1">
          <div className="flex items-center gap-2">
            <Badge variant={severityVariant}>{severity}</Badge>
            {inKev && (
              <Badge variant="critical" className="gap-1">
                <AlertTriangle className="w-3 h-3" />
                KEV
              </Badge>
            )}
          </div>
          <h4 className="font-semibold text-lg">{cve}</h4>
          {title && <p className="text-sm text-muted-foreground">{title}</p>}
        </div>
        <div className="text-right space-y-1">
          {cvss !== undefined && (
            <div className="text-sm">
              <span className="text-muted-foreground">CVSS: </span>
              <span className="font-medium">{cvss.toFixed(1)}</span>
            </div>
          )}
          {epss !== undefined && (
            <div className="text-sm">
              <span className="text-muted-foreground">EPSS: </span>
              <span className="font-medium">{(epss * 100).toFixed(2)}%</span>
            </div>
          )}
        </div>
      </div>

      {description && (
        <>
          <Button
            variant="ghost"
            size="sm"
            className="mt-2 w-full justify-between"
            onClick={() => setExpanded(!expanded)}
          >
            <span>{expanded ? 'Hide Details' : 'Show Details'}</span>
            <ChevronDown className={`w-4 h-4 transition-transform ${expanded ? 'rotate-180' : ''}`} />
          </Button>
          
          {expanded && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="mt-2 pt-2 border-t border-border"
            >
              <p className="text-sm text-muted-foreground">{description}</p>
              <div className="flex gap-2 mt-3">
                <Button size="sm" variant="outline" asChild>
                  <a href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener">
                    <ExternalLink className="w-3 h-3 mr-1" />
                    NVD
                  </a>
                </Button>
                <Button size="sm" variant="outline" asChild>
                  <a href={`https://www.cve.org/CVERecord?id=${cve}`} target="_blank" rel="noopener">
                    <ExternalLink className="w-3 h-3 mr-1" />
                    CVE.org
                  </a>
                </Button>
              </div>
            </motion.div>
          )}
        </>
      )}
    </motion.div>
  );
}

export default function IntelligenceHub() {
  const [cveSearch, setCveSearch] = useState('');

  // Fetch EPSS data
  const { data: epssData, isLoading: epssLoading, refetch: refetchEpss } = useQuery({
    queryKey: ['epss-intelligence'],
    queryFn: () => feedsApi.getEPSS(),
  });

  // Fetch KEV data
  const { data: kevData, isLoading: kevLoading, refetch: refetchKev } = useQuery({
    queryKey: ['kev-intelligence'],
    queryFn: () => feedsApi.getKEV(),
  });

  // Search specific CVE
  const { data: cveSearchResult, isLoading: cveSearchLoading, refetch: searchCve } = useQuery({
    queryKey: ['cve-search', cveSearch],
    queryFn: () => feedsApi.getKEV([cveSearch]),
    enabled: false,
  });

  const handleCveSearch = () => {
    if (cveSearch.trim()) {
      searchCve();
    }
  };

  const handleRefresh = () => {
    refetchEpss();
    refetchKev();
    toast.success('Intelligence feeds refreshed');
  };

  // Derive top vulnerabilities from real API data (EPSS + KEV)
  const kevSet = new Set(
    (kevData?.vulnerabilities || []).map((v: Record<string, string>) => v.cve_id || v.cve)
  );

  const topVulnerabilities: VulnerabilityCardProps[] = (() => {
    const items: VulnerabilityCardProps[] = [];

    // Merge EPSS scores — highest exploitation probability first
    const epssScores = (epssData?.scores || epssData?.data || []) as Array<Record<string, number | string>>;
    for (const s of epssScores.slice(0, 20)) {
      const cveId = String(s.cve || s.cve_id || '');
      const epssVal = Number(s.epss ?? s.score ?? 0);
      const cvssVal = s.cvss ? Number(s.cvss) : undefined;
      if (!cveId) continue;
      items.push({
        cve: cveId,
        severity: epssVal >= 0.7 ? 'Critical' : epssVal >= 0.4 ? 'High' : epssVal >= 0.1 ? 'Medium' : 'Low',
        epss: epssVal,
        cvss: cvssVal,
        inKev: kevSet.has(cveId),
        description: s.description as string | undefined,
      });
    }

    // Add KEV entries not already covered by EPSS
    const seenCves = new Set(items.map(i => i.cve));
    const kevVulns = (kevData?.vulnerabilities || []) as Array<Record<string, string>>;
    for (const v of kevVulns.slice(0, 10)) {
      const cveId = v.cve_id || v.cve || '';
      if (seenCves.has(cveId)) continue;
      items.push({
        cve: cveId,
        title: v.vulnerability_name || v.name,
        severity: 'Critical',
        inKev: true,
        description: v.short_description || v.description,
      });
    }

    // Sort by EPSS desc, KEV-only at the end
    return items.sort((a, b) => (b.epss ?? 0) - (a.epss ?? 0));
  })();

  const isDataLoading = epssLoading || kevLoading;

  // Full-page skeleton while initial data loads
  if (epssLoading && kevLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <div className="h-9 w-64 bg-gray-700/30 rounded-md animate-pulse" />
            <div className="h-5 w-80 bg-gray-700/20 rounded animate-pulse" />
          </div>
          <div className="h-10 w-28 bg-gray-700/20 rounded-md animate-pulse" />
        </div>
        <div className="h-14 w-full bg-gray-700/10 rounded-lg border border-gray-700/20 animate-pulse" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-36 bg-gray-700/10 rounded-lg border border-gray-700/20 animate-pulse" />
          ))}
        </div>
        <div className="h-[400px] bg-gray-700/10 rounded-lg border border-gray-700/20 animate-pulse" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Brain className="w-8 h-8 text-primary" />
            Intelligence Hub
          </h1>
          <p className="text-muted-foreground mt-1">
            Threat intelligence and vulnerability analysis
          </p>
        </div>
        <Button variant="outline" onClick={handleRefresh} className="gap-2">
          <RefreshCw className="w-4 h-4" />
          Refresh
        </Button>
      </div>

      {/* Search */}
      <Card className="glass-card">
        <CardContent className="py-4">
          <div className="flex gap-4">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search CVE (e.g., CVE-2024-3400)"
                value={cveSearch}
                onChange={(e) => setCveSearch(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleCveSearch()}
                className="pl-10"
              />
            </div>
            <Button onClick={handleCveSearch} disabled={cveSearchLoading}>
              {cveSearchLoading ? 'Searching...' : 'Search'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* CVE Search Result */}
      {cveSearchResult && (
        <Card className="glass-card border-primary/30">
          <CardHeader>
            <CardTitle>Search Result</CardTitle>
          </CardHeader>
          <CardContent>
            {cveSearchResult.vulnerabilities?.length > 0 ? (
              <VulnerabilityCard
                cve={cveSearch}
                severity="Critical"
                inKev={true}
                description="Found in CISA KEV database"
              />
            ) : (
              <p className="text-muted-foreground">
                {cveSearch} not found in KEV database. This doesn't mean it's not vulnerable.
              </p>
            )}
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="overview" className="space-y-6">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="epss">EPSS Scores</TabsTrigger>
          <TabsTrigger value="kev">Known Exploited</TabsTrigger>
          <TabsTrigger value="trending">Trending</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <Card className="glass-card">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between mb-4">
                  <TrendingUp className="w-8 h-8 text-orange-500" />
                  <Badge variant="high">Active</Badge>
                </div>
                <h3 className="text-2xl font-bold">
                  {epssLoading ? '...' : (epssData?.scores?.length || epssData?.count || 0)}
                </h3>
                <p className="text-muted-foreground">EPSS Scores Loaded</p>
              </CardContent>
            </Card>

            <Card className="glass-card">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between mb-4">
                  <AlertTriangle className="w-8 h-8 text-red-500" />
                  <Badge variant="critical">Critical</Badge>
                </div>
                <h3 className="text-2xl font-bold">
                  {kevLoading ? '...' : (kevData?.total_kev_entries || 0)}
                </h3>
                <p className="text-muted-foreground">KEV Entries</p>
              </CardContent>
            </Card>

            <Card className="glass-card">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between mb-4">
                  <Shield className="w-8 h-8 text-primary" />
                  <Badge variant="default">Online</Badge>
                </div>
                <h3 className="text-2xl font-bold">Active</h3>
                <p className="text-muted-foreground">Intelligence Feeds</p>
              </CardContent>
            </Card>
          </div>

          {/* Top Vulnerabilities */}
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>High Priority Vulnerabilities</CardTitle>
              <CardDescription>
                CVEs with highest exploitation probability — sourced from EPSS + KEV feeds
              </CardDescription>
            </CardHeader>
            <CardContent>
              {isDataLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 5 }, (_, i) => (
                    <div key={i} className="h-20 rounded-lg bg-gray-700/20 animate-pulse" />
                  ))}
                </div>
              ) : topVulnerabilities.length > 0 ? (
                <ScrollArea className="h-[400px] pr-4">
                  <div className="space-y-3">
                    {topVulnerabilities.slice(0, 15).map((vuln, index) => (
                      <motion.div
                        key={vuln.cve}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: index * 0.05 }}
                      >
                        <VulnerabilityCard {...vuln} />
                      </motion.div>
                    ))}
                  </div>
                </ScrollArea>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No vulnerability data available yet</p>
                  <p className="text-sm mt-1">EPSS and KEV feeds will populate this view</p>
                  <Button variant="outline" className="mt-4" onClick={handleRefresh}>
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Refresh Feeds
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* EPSS Tab */}
        <TabsContent value="epss" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>EPSS Distribution</CardTitle>
              <CardDescription>
                Exploit Prediction Scoring System data
              </CardDescription>
            </CardHeader>
            <CardContent>
              {epssLoading ? (
                <div className="space-y-4">
                  <div className="h-8 skeleton" />
                  <div className="h-8 skeleton w-3/4" />
                  <div className="h-8 skeleton w-1/2" />
                </div>
              ) : (epssData?.scores?.length ?? 0) > 0 ? (
                <div className="space-y-4">
                  {epssData?.scores?.slice(0, 10).map((score: any, index: number) => (
                    <div key={score.cve || index} className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span>{score.cve || `Score ${index + 1}`}</span>
                        <span className="font-medium">{((score.epss || score.score || 0) * 100).toFixed(2)}%</span>
                      </div>
                      <Progress value={(score.epss || score.score || 0) * 100} />
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <TrendingUp className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No EPSS data loaded</p>
                  <p className="text-sm">Ingest vulnerability data to see EPSS scores</p>
                  <Button variant="outline" className="mt-4" onClick={() => refetchEpss()}>
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Refresh EPSS Feed
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* KEV Tab */}
        <TabsContent value="kev" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-red-500" />
                Known Exploited Vulnerabilities
              </CardTitle>
              <CardDescription>
                CISA Known Exploited Vulnerabilities Catalog
              </CardDescription>
            </CardHeader>
            <CardContent>
              {kevLoading ? (
                <div className="space-y-4">
                  <div className="h-20 skeleton rounded-lg" />
                  <div className="h-20 skeleton rounded-lg" />
                  <div className="h-20 skeleton rounded-lg" />
                </div>
              ) : kevData?.vulnerabilities?.length > 0 ? (
                <ScrollArea className="h-[400px] pr-4">
                  <div className="space-y-3">
                    {kevData.vulnerabilities.map((vuln: any, index: number) => (
                      <VulnerabilityCard
                        key={vuln.cve_id || index}
                        cve={vuln.cve_id || vuln.cve}
                        title={vuln.vulnerability_name || vuln.name}
                        severity="Critical"
                        inKev={true}
                        description={vuln.short_description || vuln.description}
                      />
                    ))}
                  </div>
                </ScrollArea>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <AlertTriangle className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>KEV data shows {kevData?.total_kev_entries || 0} entries</p>
                  <p className="text-sm mt-2">
                    Search for specific CVEs to check KEV status
                  </p>
                  <Button variant="outline" className="mt-4" onClick={() => refetchKev()}>
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Refresh KEV Feed
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Trending Tab — KEV entries are "trending" by definition (actively exploited) */}
        <TabsContent value="trending" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Trending Vulnerabilities</CardTitle>
              <CardDescription>
                Actively exploited vulnerabilities from CISA KEV and high-EPSS CVEs
              </CardDescription>
            </CardHeader>
            <CardContent>
              {isDataLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 5 }, (_, i) => (
                    <div key={i} className="h-24 rounded-lg bg-gray-700/20 animate-pulse" />
                  ))}
                </div>
              ) : topVulnerabilities.filter(v => v.inKev || (v.epss && v.epss >= 0.5)).length > 0 ? (
                <ScrollArea className="h-[400px] pr-4">
                  <div className="space-y-3">
                    {topVulnerabilities
                      .filter(v => v.inKev || (v.epss && v.epss >= 0.5))
                      .slice(0, 15)
                      .map((vuln, index) => (
                        <motion.div
                          key={vuln.cve}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: index * 0.05 }}
                        >
                          <VulnerabilityCard
                            {...vuln}
                            description={vuln.description || (vuln.inKev
                              ? 'This vulnerability is in the CISA KEV catalog — actively exploited in the wild. Immediate patching is recommended.'
                              : `EPSS score ${((vuln.epss || 0) * 100).toFixed(1)}% — high probability of exploitation within 30 days.`
                            )}
                          />
                        </motion.div>
                      ))}
                  </div>
                </ScrollArea>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <TrendingUp className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No trending vulnerabilities detected</p>
                  <p className="text-sm mt-1">KEV and high-EPSS CVEs will appear here</p>
                  <Button variant="outline" className="mt-4" onClick={handleRefresh}>
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Refresh Feeds
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
