import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import api from '../../lib/api';

const Marketplace = () => {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchItems = async () => {
      try {
        const data = await api.settings.marketplace.browse();
        setItems(data?.items || data || []);
      } catch (error) {
        console.error('Failed to fetch marketplace', error);
      } finally {
        setLoading(false);
      }
    };
    fetchItems();
  }, []);

  const handleInstall = async (itemId: string) => {
    try {
      await api.settings.marketplace.install(itemId);
      alert('Installed successfully!');
    } catch (error) {
      console.error('Install failed', error);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold">Marketplace</h1>
      <p className="text-muted-foreground">Browse and install security integrations, compliance packs, and automation rules</p>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {loading ? (
          <div>Loading...</div>
        ) : items.length > 0 ? (
          items.map((item: any) => (
            <Card key={item.id}>
              <CardHeader>
                <CardTitle className="text-lg">{item.name}</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">{item.description || 'No description'}</p>
                <div className="flex justify-between items-center">
                  <span className="text-xs bg-gray-100 px-2 py-1 rounded">{item.category || 'General'}</span>
                  <Button size="sm" onClick={() => handleInstall(item.id)}>Install</Button>
                </div>
              </CardContent>
            </Card>
          ))
        ) : (
          <div className="col-span-3 text-center py-12 text-muted-foreground">
            No marketplace items available.
          </div>
        )}
      </div>
    </div>
  );
};

export default Marketplace;
