import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { BatteryChart, PowerChart, ProjectionChart } from "../charts";
import GlassSlabs from "../components/GlassSlabs";
import SiteFooter from "../components/SiteFooter";
import SiteHeader from "../components/SiteHeader";
import type { NavItem } from "../components/SiteHeader";
import { useEnergy, useEvents, usePoll } from "../data";
import { ExperimentTable, Scan } from "../experiment";
import { Controls, DetectionChannels, GateFeed, Incidents, StatusBar, Timeline } from "../panels";
import { Card } from "../ui";
import "../dashboard.css";

const FIXTURES = import.meta.env.VITE_USE_FIXTURES === "1";

type Tab = "overview" | "events" | "incidents" | "energy" | "experiment" | "scan" | "channels";
const TABS: { id: Tab; label: string; title: string; sub: string }[] = [
  { id: "overview", label: "Overview", title: "Overview", sub: "The link, the battery and every EnergyGate decision, live." },
  { id: "events", label: "Events", title: "Events", sub: "Everything the four detection layers have reported, newest first." },
  { id: "incidents", label: "Incidents", title: "Incidents", sub: "Correlation is rules, not ML. The ML is in the detectors." },
  { id: "energy", label: "Energy", title: "Energy", sub: "Live 1 s samples from the INA219 monitor. Markers show when the controls changed." },
  { id: "experiment", label: "Experiment", title: "Experiment", sub: "One run per condition, same attack profile (brief v4 section 6)." },
  { id: "scan", label: "Scan", title: "Scan", sub: "The console calls the ML service and stores the verdict. Benign files only, never live malware." },
  { id: "channels", label: "Channels", title: "Channels", sub: "A pluggable registry: adding a channel is a folder under channels/, not a code change. Only SMS is a trained model; the rest are labelled demos." },
];

const asTab = (v: string | null): Tab => (TABS.some(t => t.id === v) ? (v as Tab) : "overview");

export default function Dashboard() {
  const [params] = useSearchParams();
  const [tab, setTab] = useState<Tab>(asTab(params.get("tab")));
  const status = usePoll(api.status, 1000);
  const incidents = usePoll(api.incidents, 3000);
  const [profile, setProfile] = useState("loud");
  const experiment = usePoll(() => api.experiment(profile), 3000);
  const { events, error: evError, resync } = useEvents();
  const { series, resync: resyncEnergy } = useEnergy();
  const channels = usePoll(api.channels, 5000);

  const refreshAll = () => { status.refresh(); incidents.refresh(); experiment.refresh(); resync(); resyncEnergy(); channels.refresh(); };
  const simulated = !!status.data?.simulated || !!series.simulated;
  const down = status.error !== null;
  const incidentBadge = incidents.data?.filter(i => i.severity === "critical" || i.severity === "high").length ?? 0;
  // Live status and the demo controls only matter on the tabs where you watch
  // or change the run; on Events, Incidents, Experiment and Scan they were noise.
  const live = tab === "overview" || tab === "energy";
  const page = TABS.find(t => t.id === tab)!;

  const nav: NavItem[] = TABS.map(t => ({
    id: t.id, label: t.label, active: tab === t.id,
    badge: t.id === "incidents" ? incidentBadge : undefined,
    onClick: () => { setTab(t.id); window.scrollTo({ top: 0, behavior: "smooth" }); },
  }));

  const conn = FIXTURES ? { cls: " idle", text: "Fixtures, no API" } : down ? { cls: " bad", text: "API unreachable" } : { cls: "", text: "API connected" };

  return (
    <div className="site console">
      <GlassSlabs variant="quiet" />
      <SiteHeader nav={nav} action={<>
        <span className={`conn${conn.cls}`}>{conn.text}</span>
        <Link to="/" className="link">Website</Link>
      </>} />

      <main className="main wrapper dash-main">
        <div className="page-head" key={tab}>
          <h1 className="title">{page.title}</h1>
          <p className="page-sub">{page.sub}</p>
        </div>

        {FIXTURES && <div className="banner">FIXTURE MODE &mdash; showing console/frontend-kit/fixtures, not live data. Controls do nothing.</div>}
        {down && !FIXTURES && <div className="banner bad">Console API unreachable &mdash; {status.error}</div>}
        {simulated && (
          <div className="banner warn">
            SIMULATED ENERGY DATA {FIXTURES ? <>&mdash; invented fixture numbers, not measured</> : "from tools/mock_rig.py"}
          </div>
        )}

        {live && <><StatusBar s={status.data} /><Controls s={status.data} onChange={refreshAll} /></>}

        {tab === "overview" && (
          <div className="grid-main">
            <div className="col">
              <Incidents incidents={incidents.data} error={incidents.error} />
              <Card title="Battery projection"><ProjectionChart exp={experiment.data} /></Card>
            </div>
            <div className="col">
              <GateFeed events={events} />
            </div>
          </div>
        )}

        {tab === "events" && <Timeline events={events} error={evError} bare />}

        {tab === "incidents" && <Incidents incidents={incidents.data} error={incidents.error} bare />}

        {tab === "energy" && (
          <Card title="Energy" bare>
            <div className="row2">
              <PowerChart series={series} baseline={status.data?.baseline_mw ?? null} />
              <BatteryChart series={series} />
            </div>
          </Card>
        )}

        {tab === "experiment" && (
          <ExperimentTable exp={experiment.data} error={experiment.error} profile={profile}
            setProfile={p => { setProfile(p); setTimeout(experiment.refresh, 0); }} onChange={refreshAll} bare />
        )}

        {tab === "scan" && <Scan onStored={refreshAll} bare />}

        {tab === "channels" && (
          <DetectionChannels channels={channels.data?.channels ?? null} error={channels.error} onChange={refreshAll} bare />
        )}
      </main>

      <SiteFooter />
    </div>
  );
}
