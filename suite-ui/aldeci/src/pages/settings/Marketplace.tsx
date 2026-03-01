import { useState, useMemo } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { Store, Search, Download, Package, Star, Shield, Zap, Check } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';
import { api } from '../../lib/api';

// ─── Interfaces ──────────────────────────────────────────────────────────────

interface MarketplaceItem {
  id: string;
  name: string;
  description?: string;
  category?: string;
  author?: string;
  version?: string;
  installed?: boolean;
  rating?: number;
  downloads?: number;
  icon_url?: string;
}

// ─── Animation Variants ───────────────────────────────────────────────────────

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.05 } },
};

const itemVariants = {
  hidden: { opacity: 0, scale: 0.95 },
  visible: {
    opacity: 1,
    scale: 1,
    transition: { type: 'spring', stiffness: 200, damping: 22 },
  },
};

// ─── Skeleton ────────────────────────────────────────────────────────────────

function MarketplaceSkeleton() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {Array.from({ length: 6 }, (_, i) => (
        <Card key={i} className="border-gray-700/30 bg-gray-900/40">
          <CardContent className="p-5 space-y-3 animate-pulse">
            <div className="h-10 w-10 bg-gray-700/40 rounded-lg" />
            <div className="h-5 w-36 bg-gray-700/40 rounded" />
            <div className="space-y-1">
              <div className="h-3 w-full bg-gray-700/30 rounded" />
              <div className="h-3 w-3/4 bg-gray-700/30 rounded" />
            </div>
            <div className="flex justify-between items-center pt-2">
              <div className="h-5 w-20 bg-gray-700/30 rounded" />
              <div className="h-8 w-20 bg-gray-700/30 rounded" />
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ─── Category Icon Helper ─────────────────────────────────────────────────────

function CategoryIcon({ category }: { category?: string }) {
  const cat = (category || '').toLowerCase();
  if (cat === 'compliance') return <Shield className="h-5 w-5 text-blue-400" />;
  if (cat === 'automation') return <Zap className="h-5 w-5 text-yellow-400" />;
  if (cat === 'scanner') return <Search className="h-5 w-5 text-green-400" />;
  if (cat === 'integrations') return <Download className="h-5 w-5 text-purple-400" />;
  return <Store className="h-5 w-5 text-pink-400" />;
}

// ─── Item Card ────────────────────────────────────────────────────────────────

interface ItemCardProps {
  item: MarketplaceItem;
  onInstall: (id: string) => void;
  isInstalling: boolean;
}

function ItemCard({ item, onInstall, isInstalling }: ItemCardProps) {
  return (
    <motion.div variants={itemVariants}>
      <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md hover:border-gray-600/50 transition-colors h-full flex flex-col">
        <CardHeader className="pb-2">
          <div className="flex items-start gap-3">
            <div className="flex-shrink-0 h-10 w-10 rounded-lg bg-gray-800/60 flex items-center justify-center border border-gray-700/30">
              <CategoryIcon category={item.category} />
            </div>
            <div className="min-w-0 flex-1">
              <CardTitle className="text-sm font-semibold text-gray-100 leading-tight">
                {item.name}
              </CardTitle>
              {item.author && (
                <p className="text-xs text-gray-500 mt-0.5">by {item.author}</p>
              )}
            </div>
          </div>
        </CardHeader>

        <CardContent className="pt-0 flex flex-col flex-1 gap-3">
          <CardDescription className="text-gray-400 text-sm line-clamp-2 flex-1">
            {item.description || 'No description available.'}
          </CardDescription>

          <div className="flex flex-wrap gap-1.5">
            {item.category && (
              <Badge className="bg-gray-700/40 text-gray-300 border-gray-600/30 text-xs">
                {item.category}
              </Badge>
            )}
            {item.version && (
              <Badge variant="outline" className="border-gray-700/30 text-gray-500 text-xs">
                v{item.version}
              </Badge>
            )}
          </div>

          <div className="flex items-center justify-between pt-1">
            <div className="flex items-center gap-3 text-xs text-gray-500">
              {item.rating !== undefined && (
                <span className="flex items-center gap-1">
                  <Star className="h-3 w-3 text-yellow-400 fill-yellow-400" />
                  {item.rating.toFixed(1)}
                </span>
              )}
              {item.downloads !== undefined && (
                <span className="flex items-center gap-1">
                  <Download className="h-3 w-3" />
                  {item.downloads.toLocaleString()}
                </span>
              )}
            </div>

            {item.installed ? (
              <Badge className="bg-green-900/30 text-green-400 border-green-700/30 gap-1">
                <Check className="h-3 w-3" />
                Installed
              </Badge>
            ) : (
              <Button
                size="sm"
                disabled={isInstalling}
                onClick={() => onInstall(item.id)}
                className="bg-primary/20 hover:bg-primary/30 text-primary border border-primary/30 h-7 text-xs"
              >
                {isInstalling ? 'Installing…' : 'Install'}
              </Button>
            )}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function Marketplace() {
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');

  const { data: itemsRaw, isLoading } = useQuery({
    queryKey: ['marketplace'],
    queryFn: async () => {
      const res = await api.get('/api/v1/marketplace');
      return res.data?.items || res.data || [];
    },
  });

  const items = useMemo(() => {
    let list = (itemsRaw || []) as MarketplaceItem[];
    if (categoryFilter !== 'all') {
      list = list.filter(item => item.category?.toLowerCase() === categoryFilter);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        item =>
          item.name.toLowerCase().includes(q) ||
          (item.description || '').toLowerCase().includes(q),
      );
    }
    return list;
  }, [itemsRaw, searchQuery, categoryFilter]);

  const installMutation = useMutation({
    mutationFn: async (itemId: string) => {
      await api.post(`/api/v1/marketplace/${itemId}/install`);
    },
    onSuccess: () => toast.success('Integration installed successfully'),
    onError: () => toast.error('Installation failed'),
  });

  const allItems = (itemsRaw || []) as MarketplaceItem[];
  const installedCount = allItems.filter(i => i.installed).length;
  const categorySet = new Set(allItems.map(i => i.category?.toLowerCase()).filter(Boolean));
  const categoryCount = categorySet.size;

  const categories = ['all', 'integrations', 'compliance', 'automation', 'scanner'];

  return (
    <div className="p-6 space-y-8">
      {/* Header */}
      <div className="space-y-1">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-pink-500/20 via-purple-500/20 to-indigo-500/20 border border-gray-700/30 flex items-center justify-center">
            <Store className="h-5 w-5 text-purple-400" />
          </div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-pink-400 via-purple-400 to-indigo-400 bg-clip-text text-transparent">
            Marketplace
          </h1>
        </div>
        <p className="text-gray-400 text-sm pl-1">
          Browse and install security integrations, compliance packs, and automation rules
        </p>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Total Items', value: allItems.length, icon: Package },
          { label: 'Installed', value: installedCount, icon: Check },
          { label: 'Categories', value: categoryCount, icon: Store },
        ].map(({ label, value, icon: Icon }) => (
          <Card key={label} className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardContent className="p-4 flex items-center gap-3">
              <div className="h-9 w-9 rounded-lg bg-gray-800/60 border border-gray-700/30 flex items-center justify-center flex-shrink-0">
                <Icon className="h-4 w-4 text-gray-400" />
              </div>
              <div>
                <p className="text-xl font-bold text-gray-100">{value}</p>
                <p className="text-xs text-gray-500">{label}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Search + Category Filter */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500 pointer-events-none" />
          <Input
            placeholder="Search integrations..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="pl-9 bg-gray-900/40 border-gray-700/30 text-gray-200 placeholder:text-gray-600 focus-visible:ring-primary/30"
          />
        </div>
        <div className="flex gap-2 flex-wrap">
          {categories.map(cat => (
            <button
              key={cat}
              onClick={() => setCategoryFilter(cat)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                categoryFilter === cat
                  ? 'bg-primary/20 text-primary border border-primary/30'
                  : 'text-gray-400 hover:text-gray-300 border border-gray-700/30'
              }`}
            >
              {cat.charAt(0).toUpperCase() + cat.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Grid */}
      {isLoading ? (
        <MarketplaceSkeleton />
      ) : items.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-center gap-4">
          <div className="h-14 w-14 rounded-2xl bg-gray-800/60 border border-gray-700/30 flex items-center justify-center">
            <Package className="h-7 w-7 text-gray-600" />
          </div>
          <div>
            <p className="text-gray-300 font-medium">No marketplace items found</p>
            <p className="text-gray-600 text-sm mt-1">
              {searchQuery || categoryFilter !== 'all'
                ? 'Try adjusting your search or filter'
                : 'Check back later for new integrations'}
            </p>
          </div>
        </div>
      ) : (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"
        >
          {items.map(item => (
            <ItemCard
              key={item.id}
              item={item}
              onInstall={id => installMutation.mutate(id)}
              isInstalling={installMutation.isPending && installMutation.variables === item.id}
            />
          ))}
        </motion.div>
      )}
    </div>
  );
}
