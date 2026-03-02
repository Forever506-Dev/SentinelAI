import pathlib

dash_dir = pathlib.Path(r"F:\SentinelAI\panel\src\app\(authenticated)\dashboard")
dash_dir.mkdir(parents=True, exist_ok=True)

content = '''import { StatsOverview } from "@/components/dashboard/stats-overview";
import { ThreatFeed } from "@/components/dashboard/threat-feed";
import { AgentStatusGrid } from "@/components/dashboard/agent-status";

export default function DashboardPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <p className="text-sm text-cyber-muted mt-1">Real-time threat monitoring and agent overview</p>
      </div>

      <StatsOverview />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ThreatFeed />
        <AgentStatusGrid />
      </div>
    </div>
  );
}
'''

(dash_dir / "page.tsx").write_text(content, encoding="utf-8")
print("Dashboard page created!")
