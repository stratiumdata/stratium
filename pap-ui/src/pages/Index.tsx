import { Layout } from '@/components/Layout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, Award, FileText, Activity, Loader2 } from 'lucide-react';
import { usePolicies } from '@/hooks/use-policies';
import { useEntitlements } from '@/hooks/use-entitlements';
import { useAuditLogs } from '@/hooks/use-audit-logs';

const Index = () => {
  const { data: policiesData, isLoading: policiesLoading } = usePolicies();
  const { data: entitlementsData, isLoading: entitlementsLoading } = useEntitlements();
  const { data: auditLogsData, isLoading: auditLogsLoading } = useAuditLogs();

  const policies = policiesData?.policies || [];
  const entitlements = entitlementsData?.entitlements || [];
  const auditLogs = auditLogsData?.audit_logs || [];

  const isLoading = policiesLoading || entitlementsLoading || auditLogsLoading;

  const stats = [
    {
      title: 'Active Policies',
      value: policies.filter(p => p.enabled).length,
      total: policies.length,
      icon: Shield,
      color: 'text-primary',
    },
    {
      title: 'Active Entitlements',
      value: entitlements.filter(e => e.enabled).length,
      total: entitlements.length,
      icon: Award,
      color: 'text-accent',
    },
    {
      title: 'Recent Activities',
      value: auditLogs.length,
      total: auditLogs.filter(log => {
        const logDate = new Date(log.timestamp);
        const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        return logDate > dayAgo;
      }).length,
      icon: Activity,
      color: 'text-blue-400',
    },
    {
      title: 'Audit Logs',
      value: auditLogs.length,
      total: auditLogs.length,
      icon: FileText,
      color: 'text-purple-400',
    },
  ];

  if (isLoading) {
    return (
      <Layout>
        <div className="flex justify-center items-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="space-y-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground">Dashboard</h1>
          <p className="text-muted-foreground mt-2">
            Overview of your policy and entitlement management system
          </p>
        </div>

        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          {stats.map((stat) => {
            const Icon = stat.icon;
            return (
              <Card key={stat.title}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">{stat.title}</CardTitle>
                  <Icon className={`h-4 w-4 ${stat.color}`} />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{stat.total}</div>
                  <p className="text-xs text-muted-foreground">
                    {stat.value} active
                  </p>
                </CardContent>
              </Card>
            );
          })}
        </div>

        <div className="grid gap-6 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Recent Policies</CardTitle>
              <CardDescription>Latest policy updates</CardDescription>
            </CardHeader>
            <CardContent>
              {policies.slice(0, 5).length > 0 ? (
                <div className="space-y-4">
                  {policies.slice(0, 5).map(policy => (
                    <div key={policy.id} className="flex items-center justify-between border-b border-border pb-3 last:border-0">
                      <div className="flex-1 min-w-0">
                        <p className="font-medium truncate">{policy.name}</p>
                        <p className="text-sm text-muted-foreground truncate">{policy.description}</p>
                      </div>
                      <div className={`ml-4 rounded-full px-2 py-1 text-xs ${
                        policy.enabled ? 'bg-accent/20 text-accent' : 'bg-muted text-muted-foreground'
                      }`}>
                        {policy.enabled ? 'Active' : 'Inactive'}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">No policies yet</p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Recent Entitlements</CardTitle>
              <CardDescription>Latest entitlement updates</CardDescription>
            </CardHeader>
            <CardContent>
              {entitlements.slice(0, 5).length > 0 ? (
                <div className="space-y-4">
                  {entitlements.slice(0, 5).map(entitlement => (
                    <div key={entitlement.id} className="flex items-center justify-between border-b border-border pb-3 last:border-0">
                      <div className="flex-1 min-w-0">
                        <p className="font-medium truncate">{entitlement.name}</p>
                        <p className="text-sm text-muted-foreground truncate">{entitlement.description}</p>
                      </div>
                      <div className={`ml-4 rounded-full px-2 py-1 text-xs ${
                        entitlement.enabled ? 'bg-accent/20 text-accent' : 'bg-muted text-muted-foreground'
                      }`}>
                        {entitlement.enabled ? 'Active' : 'Inactive'}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">No entitlements yet</p>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </Layout>
  );
};

export default Index;
