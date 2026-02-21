import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Swords,
  Shield,
  Activity,
  AlertTriangle,
  Network,
} from 'lucide-react';
import { Card, CardContent } from '../../components/ui/card';
import { Badge } from '../../components/ui/badge';
import MPTEChat from '../../components/attack/MPTEChat';
import { microPentestApi, reachabilityApi, graphApi } from '../../lib/api';

export default function AttackSimulation() {
  // Fetch attack simulation status
  const { data: pentestStatus } = useQuery({
    queryKey: ['pentest-health'],
    queryFn: () => microPentestApi.getHealth(),
    retry: false,
  });

  // Fetch reachability metrics
  const { data: reachabilityData } = useQuery({
    queryKey: ['reachability-metrics'],
    queryFn: () => reachabilityApi.getMetrics(),
    retry: false,
  });

  // Fetch attack graph data
  const { data: graphData } = useQuery({
    queryKey: ['attack-graph'],
    queryFn: () => graphApi.getGraph(),
    retry: false,
  });

  const stats = [
    {
      label: 'Active Simulations',
      value: (pentestStatus as any)?.active_simulations || 0,
      icon: Activity,
      color: 'text-blue-400',
    },
    {
      label: 'Attack Paths',
      value: (graphData as any)?.attack_paths?.length || (graphData as any)?.paths?.length || (graphData as any)?.total_paths || 0,
      icon: Network,
      color: 'text-purple-400',
    },
    {
      label: 'Critical Paths',
      value: (reachabilityData as any)?.critical_reachable || 0,
      icon: AlertTriangle,
      color: 'text-red-400',
    },
    {
      label: 'Blocked',
      value: (reachabilityData as any)?.blocked_paths || 0,
      icon: Shield,
      color: 'text-green-400',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-red-500 to-orange-500 flex items-center justify-center">
              <Swords className="w-5 h-5 text-white" />
            </div>
            Attack Lab
          </h1>
          <p className="text-muted-foreground mt-1">
            AI-powered attack simulation and penetration testing
          </p>
        </div>
        <Badge 
          variant="outline" 
          className={(pentestStatus as any)?.status === 'ready' 
            ? 'border-green-500/30 text-green-400' 
            : 'border-yellow-500/30 text-yellow-400'
          }
        >
          <span className={`w-2 h-2 rounded-full mr-2 ${
            (pentestStatus as any)?.status === 'ready' ? 'bg-green-500' : 'bg-yellow-500'
          }`} />
          {(pentestStatus as any)?.status || 'Initializing'}
        </Badge>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {stats.map((stat, index) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
          >
            <Card className="glass-card">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg bg-muted/50 ${stat.color}`}>
                    <stat.icon className="w-5 h-5" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold">{stat.value}</p>
                    <p className="text-xs text-muted-foreground">{stat.label}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Main Chat Interface */}
      <MPTEChat />
    </div>
  );
}
