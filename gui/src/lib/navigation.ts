// The sidebar's tab list, shared with the command palette so the two cannot
// drift apart (the ten-event webhook picker in ui/index.ts's own comment is
// what a copied list looks like once it does).

export interface NavItem {
  id: string;
  label: string;
  /** Set on the first item of a new group; renders a group heading above it. */
  section?: string;
}

export const PRIMARY_TABS: NavItem[] = [
  { id: "dashboard", label: "Home", section: "Core" },
  { id: "sessions", label: "History" },
  { id: "policies", label: "Policy", section: "Govern" },
  { id: "tripwire", label: "Tripwire" },
  { id: "access", label: "Access", section: "Admin" },
  { id: "settings", label: "Settings" },
];

export const DEVELOPER_TABS: NavItem[] = [
  { id: "testing", label: "Testing", section: "Developer" },
  { id: "metrics", label: "Prometheus" },
  { id: "livedashboard", label: "Live Feed" },
  { id: "devhub", label: "Dev Hub" },
];

/** The sidebar's own ordering rule: primary tabs, plus the developer tabs
 *  when they are turned on. */
export function visibleTabs(showDeveloperTools: boolean): NavItem[] {
  return showDeveloperTools ? [...PRIMARY_TABS, ...DEVELOPER_TABS] : PRIMARY_TABS;
}
