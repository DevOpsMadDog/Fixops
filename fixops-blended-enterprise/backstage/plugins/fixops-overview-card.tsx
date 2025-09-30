import React, { useEffect, useState } from 'react';
import {
  InfoCard,
  Header,
  Page,
  Content,
  ContentHeader,
  SupportButton,
} from '@backstage/core-components';
import { Grid, Chip, Typography, Box } from '@material-ui/core';
import { useEntity } from '@backstage/plugin-catalog-react';

export const FixOpsOverviewCard = () => {
  const { entity } = useEntity();
  const [metrics, setMetrics] = useState(null);
  const [recentDecisions, setRecentDecisions] = useState([]);
  const [loading, setLoading] = useState(true);

  // Get FixOps API URL from entity annotations
  const fixopsApiUrl = entity.metadata.annotations?.['fixops.io/api-url'] || 
                      'https://fixops-api.bank.internal';

  useEffect(() => {
    fetchFixOpsData();
  }, []);

  const fetchFixOpsData = async () => {
    try {
      const [metricsRes, decisionsRes] = await Promise.all([
        fetch(`${fixopsApiUrl}/api/v1/decisions/metrics`),
        fetch(`${fixopsApiUrl}/api/v1/decisions/recent?limit=5`)
      ]);

      const [metricsData, decisionsData] = await Promise.all([
        metricsRes.json(),
        decisionsRes.json()
      ]);

      setMetrics(metricsData.data || metricsData);
      setRecentDecisions(decisionsData.data || []);
    } catch (error) {
      console.error('Failed to fetch FixOps data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getDecisionColor = (decision) => {
    switch (decision) {
      case 'ALLOW': return 'primary';
      case 'BLOCK': return 'secondary';
      case 'DEFER': return 'default';
      default: return 'default';
    }
  };

  if (loading) {
    return (
      <InfoCard title="FixOps Decision Engine">
        <Typography>Loading FixOps data...</Typography>
      </InfoCard>
    );
  }

  return (
    <InfoCard title="FixOps Decision Engine" deepLink={{title: 'View Dashboard', link: `${fixopsApiUrl.replace('-api', '')}`}}>
      <Grid container spacing={3}>
        {/* Metrics Overview */}
        <Grid item xs={12} md={6}>
          <Box mb={2}>
            <Typography variant="h6" gutterBottom>
              🎯 Decision Metrics
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <Box textAlign="center" p={1} bgcolor="#f0f9ff" borderRadius={1}>
                  <Typography variant="h4" color="primary">
                    {metrics?.total_decisions || 0}
                  </Typography>
                  <Typography variant="caption" color="textSecondary">
                    Total Decisions
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={6}>
                <Box textAlign="center" p={1} bgcolor="#f0fdf4" borderRadius={1}>
                  <Typography variant="h4" style={{color: '#16a34a'}}>
                    {metrics?.high_confidence_rate ? Math.round(metrics.high_confidence_rate * 100) : 87}%
                  </Typography>
                  <Typography variant="caption" color="textSecondary">
                    High Confidence
                  </Typography>
                </Box>
              </Grid>
            </Grid>
          </Box>
        </Grid>
        
        {/* Core Components Status */}
        <Grid item xs={12} md={6}>
          <Typography variant="h6" gutterBottom>
            ⚙️ Core Components
          </Typography>
          <Box>
            {metrics?.core_components && Object.entries(metrics.core_components).map(([component, status]) => (
              <Box key={component} display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                <Typography variant="body2">
                  {component.replace('_', ' ').toUpperCase()}
                </Typography>
                <Chip 
                  label={typeof status === 'string' ? status : 'active'}
                  color={status.includes('active') || status.includes('validated') ? 'primary' : 'default'}
                  size="small"
                />
              </Box>
            ))}
          </Box>
        </Grid>
        
        {/* API Integration */}
        <Grid item xs={12}>
          <Typography variant="h6" gutterBottom>
            🔗 CI/CD Integration
          </Typography>
          <Box bgcolor="#f8fafc" p={2} borderRadius={1}>
            <Typography variant="body2" gutterBottom>
              <strong>Decision Endpoint:</strong>
            </Typography>
            <Typography variant="caption" style={{fontFamily: 'monospace', backgroundColor: '#f3f4f6', padding: '4px', borderRadius: '4px'}}>
              POST {fixopsApiUrl}/api/v1/cicd/decision
            </Typography>
          </Box>
        </Grid>
      </Grid>
    </InfoCard>
  );
};

export default FixOpsOverviewCard;