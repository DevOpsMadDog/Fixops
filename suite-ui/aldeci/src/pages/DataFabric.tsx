import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Database,
  Upload,
  FileJson,
  FileCode,
  AlertCircle,
  RefreshCw,
  Play,
  Loader2,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { ingestApi, feedsApi } from '../lib/api';
import { toast } from 'sonner';

interface DataSource {
  id: string;
  name: string;
  type: string;
  format: string;
  status: 'active' | 'pending' | 'error';
  lastSync?: string;
  recordCount?: number;
}

export default function DataFabric() {
  const [searchQuery, setSearchQuery] = useState('');
  const [sbomFile, setSbomFile] = useState<File | null>(null);
  const [sarifFile, setSarifFile] = useState<File | null>(null);
  const queryClient = useQueryClient();

  // Real API calls
  const { data: epssData, isLoading: epssLoading, refetch: refetchEpss } = useQuery({
    queryKey: ['epss-feed'],
    queryFn: () => feedsApi.getEPSS(),
  });

  const { data: kevData, isLoading: kevLoading, refetch: refetchKev } = useQuery({
    queryKey: ['kev-feed'],
    queryFn: () => feedsApi.getKEV(),
  });

  // SBOM ingest mutation
  const sbomMutation = useMutation({
    mutationFn: async (file: File) => {
      return ingestApi.ingestSBOM(file);
    },
    onSuccess: (data) => {
      toast.success('SBOM ingested successfully', {
        description: `Processed ${data.component_count || 'N/A'} components`,
      });
      queryClient.invalidateQueries({ queryKey: ['sbom'] });
      setSbomFile(null);
    },
    onError: (error: any) => {
      toast.error('Failed to ingest SBOM', {
        description: error.response?.data?.detail || error.message,
      });
    },
  });

  // SARIF ingest mutation
  const sarifMutation = useMutation({
    mutationFn: async (file: File) => {
      return ingestApi.ingestSARIF(file);
    },
    onSuccess: (data) => {
      toast.success('SARIF ingested successfully', {
        description: `Found ${data.finding_count || 'N/A'} findings`,
      });
      queryClient.invalidateQueries({ queryKey: ['sarif'] });
      setSarifFile(null);
    },
    onError: (error: any) => {
      toast.error('Failed to ingest SARIF', {
        description: error.response?.data?.detail || error.message,
      });
    },
  });

  const handleSbomUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSbomFile(file);
    }
  };

  const handleSarifUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSarifFile(file);
    }
  };

  const handleRefreshFeeds = () => {
    refetchEpss();
    refetchKev();
    toast.success('Feeds refreshed');
  };

  // Data sources from real API data
  const dataSources: DataSource[] = [
    {
      id: 'epss',
      name: 'EPSS Feed',
      type: 'Threat Intelligence',
      format: 'JSON',
      status: epssData ? 'active' : 'pending',
      recordCount: epssData?.scores?.length || epssData?.count || 0,
    },
    {
      id: 'kev',
      name: 'CISA KEV',
      type: 'Threat Intelligence',
      format: 'JSON',
      status: kevData ? 'active' : 'pending',
      recordCount: kevData?.total_kev_entries || kevData?.vulnerabilities?.length || 0,
    },
  ];

  const supportedFormats = [
    { id: 'sbom', name: 'SBOM (CycloneDX)', icon: FileJson, description: 'Software Bill of Materials' },
    { id: 'sarif', name: 'SARIF', icon: FileCode, description: 'Static Analysis Results' },
    { id: 'sast', name: 'SAST', icon: FileCode, description: 'Static Application Security Testing' },
    { id: 'dast', name: 'DAST', icon: FileCode, description: 'Dynamic Application Security Testing' },
    { id: 'sca', name: 'SCA', icon: FileJson, description: 'Software Composition Analysis' },
    { id: 'cnapp', name: 'CNAPP', icon: FileJson, description: 'Cloud-Native App Protection' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Database className="w-8 h-8 text-primary" />
            Data Fabric
          </h1>
          <p className="text-muted-foreground mt-1">
            Unified security data ingestion and normalization
          </p>
        </div>
        <Button variant="outline" onClick={handleRefreshFeeds} className="gap-2">
          <RefreshCw className="w-4 h-4" />
          Refresh Feeds
        </Button>
      </div>

      <Tabs defaultValue="ingest" className="space-y-6">
        <TabsList>
          <TabsTrigger value="ingest">Data Ingestion</TabsTrigger>
          <TabsTrigger value="sources">Data Sources</TabsTrigger>
          <TabsTrigger value="feeds">Threat Feeds</TabsTrigger>
        </TabsList>

        {/* Ingestion Tab */}
        <TabsContent value="ingest" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* SBOM Upload */}
            <Card className="glass-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileJson className="w-5 h-5 text-primary" />
                  SBOM Ingestion
                </CardTitle>
                <CardDescription>
                  Upload CycloneDX or SPDX format SBOM files
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="border-2 border-dashed border-border rounded-lg p-6 text-center">
                  <Upload className="w-10 h-10 mx-auto text-muted-foreground mb-4" />
                  <input
                    type="file"
                    accept=".json,.xml"
                    onChange={handleSbomUpload}
                    className="hidden"
                    id="sbom-upload"
                  />
                  <label htmlFor="sbom-upload" className="cursor-pointer">
                    <p className="text-sm text-muted-foreground">
                      Click to upload or drag and drop
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      CycloneDX JSON/XML or SPDX format
                    </p>
                  </label>
                </div>
                
                {sbomFile && (
                  <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                    <div className="flex items-center gap-2">
                      <FileJson className="w-4 h-4" />
                      <span className="text-sm">{sbomFile.name}</span>
                    </div>
                    <Button 
                      size="sm" 
                      onClick={() => sbomMutation.mutate(sbomFile)}
                      disabled={sbomMutation.isPending}
                    >
                      {sbomMutation.isPending ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <>
                          <Play className="w-4 h-4 mr-1" />
                          Ingest
                        </>
                      )}
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* SARIF Upload */}
            <Card className="glass-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileCode className="w-5 h-5 text-primary" />
                  SARIF Ingestion
                </CardTitle>
                <CardDescription>
                  Upload static analysis results in SARIF format
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="border-2 border-dashed border-border rounded-lg p-6 text-center">
                  <Upload className="w-10 h-10 mx-auto text-muted-foreground mb-4" />
                  <input
                    type="file"
                    accept=".sarif,.json"
                    onChange={handleSarifUpload}
                    className="hidden"
                    id="sarif-upload"
                  />
                  <label htmlFor="sarif-upload" className="cursor-pointer">
                    <p className="text-sm text-muted-foreground">
                      Click to upload or drag and drop
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      SARIF 2.1.0 format
                    </p>
                  </label>
                </div>
                
                {sarifFile && (
                  <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                    <div className="flex items-center gap-2">
                      <FileCode className="w-4 h-4" />
                      <span className="text-sm">{sarifFile.name}</span>
                    </div>
                    <Button 
                      size="sm" 
                      onClick={() => sarifMutation.mutate(sarifFile)}
                      disabled={sarifMutation.isPending}
                    >
                      {sarifMutation.isPending ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <>
                          <Play className="w-4 h-4 mr-1" />
                          Ingest
                        </>
                      )}
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Supported Formats */}
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Supported Formats</CardTitle>
              <CardDescription>
                Security data formats that can be ingested and normalized
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                {supportedFormats.map((format) => {
                  const Icon = format.icon;
                  return (
                    <motion.div
                      key={format.id}
                      whileHover={{ scale: 1.02 }}
                      className="p-4 rounded-lg border border-border bg-muted/30 text-center cursor-pointer hover:border-primary/50 transition-colors"
                    >
                      <Icon className="w-8 h-8 mx-auto text-primary mb-2" />
                      <p className="font-medium text-sm">{format.name}</p>
                      <p className="text-xs text-muted-foreground">{format.description}</p>
                    </motion.div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Data Sources Tab */}
        <TabsContent value="sources" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Connected Data Sources</CardTitle>
                  <CardDescription>Active data feeds and integrations</CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <Input
                    placeholder="Search sources..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-64"
                  />
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {dataSources.map((source, index) => (
                  <motion.div
                    key={source.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="flex items-center justify-between p-4 rounded-lg border border-border bg-muted/30"
                  >
                    <div className="flex items-center gap-4">
                      <div className={`w-3 h-3 rounded-full ${
                        source.status === 'active' ? 'bg-green-500' :
                        source.status === 'pending' ? 'bg-yellow-500' : 'bg-red-500'
                      }`} />
                      <div>
                        <p className="font-medium">{source.name}</p>
                        <p className="text-sm text-muted-foreground">{source.type}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <Badge variant="outline">{source.format}</Badge>
                      <div className="text-right">
                        <p className="text-sm font-medium">{source.recordCount?.toLocaleString()} records</p>
                        <p className="text-xs text-muted-foreground">
                          {source.status === 'active' ? 'Live' : 'Pending'}
                        </p>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Feeds Tab */}
        <TabsContent value="feeds" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* EPSS Feed */}
            <Card className="glass-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertCircle className="w-5 h-5 text-orange-500" />
                  EPSS Feed
                </CardTitle>
                <CardDescription>
                  Exploit Prediction Scoring System
                </CardDescription>
              </CardHeader>
              <CardContent>
                {epssLoading ? (
                  <div className="space-y-3">
                    <div className="h-4 skeleton w-full" />
                    <div className="h-4 skeleton w-3/4" />
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-muted-foreground">Scores Loaded</span>
                      <span className="font-bold">{epssData?.scores?.length || epssData?.count || 0}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-muted-foreground">Status</span>
                      <Badge variant={epssData ? 'default' : 'secondary'}>
                        {epssData ? 'Active' : 'Inactive'}
                      </Badge>
                    </div>
                    <Button 
                      variant="outline" 
                      className="w-full"
                      onClick={() => refetchEpss()}
                    >
                      <RefreshCw className="w-4 h-4 mr-2" />
                      Refresh Feed
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* KEV Feed */}
            <Card className="glass-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertCircle className="w-5 h-5 text-red-500" />
                  CISA KEV
                </CardTitle>
                <CardDescription>
                  Known Exploited Vulnerabilities
                </CardDescription>
              </CardHeader>
              <CardContent>
                {kevLoading ? (
                  <div className="space-y-3">
                    <div className="h-4 skeleton w-full" />
                    <div className="h-4 skeleton w-3/4" />
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-muted-foreground">Total Entries</span>
                      <span className="font-bold">{kevData?.total_kev_entries || 0}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-muted-foreground">Status</span>
                      <Badge variant={kevData ? 'default' : 'secondary'}>
                        {kevData ? 'Active' : 'Inactive'}
                      </Badge>
                    </div>
                    <Button 
                      variant="outline" 
                      className="w-full"
                      onClick={() => refetchKev()}
                    >
                      <RefreshCw className="w-4 h-4 mr-2" />
                      Refresh Feed
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
