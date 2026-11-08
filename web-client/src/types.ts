export interface Asset {
  id: string;
  name: string;
  ip: string;
  type: string;
  criticality: number;
  riskScore: number;
  status: string;
}

export interface NetLink {
  id: string;
  source: string;
  target: string;
  baseCost: number;
  bandwidth: number;
  status: string;
}

export interface IncidentRow {
  id: string;
  sourceIp: string;
  status: string;
  openedAt: string;
  alerts: import("./alerts").FeedAlert[];
}

export interface FlowRow {
  id: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  bytesOut: number;
  bytesIn: number;
  packets: number;
  startTime: string;
  endTime: string;
  durationMs: number;
  flags: string[];
  label: string;
  simulated: boolean;
  ended: boolean;
}

export interface PlanTeam {
  team: string;
  tasks: string[];
  taskDetails?: { id: string; hostId: string; hostName: string; value: number; cost: number }[];
}

export interface PlanLinkEnd {
  id: string;
  sourceId: string;
  sourceName: string;
  targetId: string;
  targetName: string;
}

export interface SocTeam {
  name: string;
  capacity: number;
}

export interface PlanBody {
  backbone: {
    links: string[];
    totalWeight: number;
    connected: boolean;
    unreachable: string[];
    linkEnds?: PlanLinkEnd[];
  };
  assignment: {
    teams: PlanTeam[];
    totalValue: number;
    excluded: string[];
    stateCount: number;
    excludedHosts?: string[];
    teamsMeta?: SocTeam[];
  };
}
