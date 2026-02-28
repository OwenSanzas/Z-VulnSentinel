"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { AuthGuard } from "@/components/auth-guard";
import { useAuth } from "@/hooks/use-auth";
import { useThemeStore } from "@/lib/theme-store";
import { Breadcrumb, type BreadcrumbItem } from "@/components/breadcrumb";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard,
  FolderOpen,
  ShieldAlert,
  Library,
  LogOut,
  Shield,
  CalendarClock,
  ShieldX,
  PanelLeftClose,
  PanelLeft,
  Sun,
  Moon,
} from "lucide-react";

interface NavItem {
  href: string;
  label: string;
  icon: React.ElementType;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const navSections: NavSection[] = [
  {
    title: "OVERVIEW",
    items: [{ href: "/", label: "Dashboard", icon: LayoutDashboard }],
  },
  {
    title: "MONITORING",
    items: [
      { href: "/projects", label: "Projects", icon: FolderOpen },
      { href: "/libraries", label: "Libraries", icon: Library },
      { href: "/events", label: "Events", icon: CalendarClock },
    ],
  },
  {
    title: "SECURITY",
    items: [
      { href: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert },
      { href: "/upstream-vulns", label: "Upstream Vulns", icon: ShieldX },
    ],
  },
];

function isActive(pathname: string, href: string) {
  if (href === "/") return pathname === "/";
  return pathname.startsWith(href);
}

function getBreadcrumbs(pathname: string): BreadcrumbItem[] {
  const crumbs: BreadcrumbItem[] = [{ label: "Home", href: "/" }];
  if (pathname === "/") return crumbs;

  const segments = pathname.split("/").filter(Boolean);
  const first = segments[0];

  const labelMap: Record<string, string> = {
    projects: "Projects",
    libraries: "Libraries",
    events: "Events",
    vulnerabilities: "Vulnerabilities",
    "upstream-vulns": "Upstream Vulns",
    project: "Projects",
    library: "Libraries",
    event: "Events",
    "upstream-vuln": "Upstream Vulns",
    "client-vuln": "Vulnerabilities",
  };

  const hrefMap: Record<string, string> = {
    project: "/projects",
    library: "/libraries",
    event: "/events",
    "upstream-vuln": "/upstream-vulns",
    "client-vuln": "/vulnerabilities",
  };

  if (segments.length === 1) {
    crumbs.push({ label: labelMap[first] || first });
  } else {
    crumbs.push({
      label: labelMap[first] || first,
      href: hrefMap[first] || `/${first}`,
    });
    crumbs.push({ label: "Detail" });
  }

  return crumbs;
}

function Sidebar({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  const pathname = usePathname();
  const { logout } = useAuth();

  return (
    <aside
      className={cn(
        "flex h-screen flex-col border-r border-[var(--color-sidebar-border)] bg-[var(--color-sidebar)] transition-all duration-200",
        collapsed ? "w-12" : "w-48"
      )}
    >
      {/* Logo */}
      <div className="flex items-center gap-2 border-b border-[var(--color-sidebar-border)] px-3 py-2.5">
        <Shield className="h-4 w-4 text-primary shrink-0" />
        {!collapsed && (
          <span className="font-semibold text-xs text-[var(--color-sidebar-foreground)]">
            VulnSentinel
          </span>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-2 py-2 space-y-3">
        {navSections.map((section) => (
          <div key={section.title}>
            {!collapsed && (
              <div className="px-2 mb-1 text-[9px] font-semibold uppercase tracking-widest text-[var(--color-sidebar-muted)]">
                {section.title}
              </div>
            )}
            <div className="space-y-px">
              {section.items.map((item) => {
                const active = isActive(pathname, item.href);
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    title={collapsed ? item.label : undefined}
                    className={cn(
                      "flex items-center gap-2 rounded px-2 py-1.5 text-xs font-medium transition-colors",
                      active
                        ? "bg-[var(--color-sidebar-accent)] text-[var(--color-sidebar-active)] font-semibold"
                        : "text-[var(--color-sidebar-muted)] hover:bg-[var(--color-sidebar-accent)] hover:text-[var(--color-sidebar-foreground)]"
                    )}
                  >
                    <item.icon className="h-3.5 w-3.5 shrink-0" />
                    {!collapsed && item.label}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="border-t border-[var(--color-sidebar-border)] px-2 py-2 space-y-px">
        <button
          onClick={logout}
          className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-xs text-[var(--color-sidebar-muted)] hover:bg-[var(--color-sidebar-accent)] hover:text-[var(--color-sidebar-foreground)] transition-colors"
        >
          <LogOut className="h-3.5 w-3.5 shrink-0" />
          {!collapsed && "Sign out"}
        </button>
        <button
          onClick={onToggle}
          className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-xs text-[var(--color-sidebar-muted)] hover:bg-[var(--color-sidebar-accent)] hover:text-[var(--color-sidebar-foreground)] transition-colors"
        >
          {collapsed ? (
            <PanelLeft className="h-3.5 w-3.5 shrink-0" />
          ) : (
            <>
              <PanelLeftClose className="h-3.5 w-3.5 shrink-0" />
              Collapse
            </>
          )}
        </button>
      </div>
    </aside>
  );
}

function TopBar() {
  const pathname = usePathname();
  const breadcrumbs = getBreadcrumbs(pathname);
  const { theme, toggle } = useThemeStore();

  return (
    <header className="flex items-center justify-between border-b bg-background px-4 py-2">
      <Breadcrumb items={breadcrumbs} />
      <div className="flex items-center gap-3">
        <span className="text-[11px] text-muted-foreground">O2Lab</span>
        <button
          onClick={toggle}
          className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
          title={theme === "dark" ? "Switch to light" : "Switch to dark"}
        >
          {theme === "dark" ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
        </button>
      </div>
    </header>
  );
}

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <AuthGuard>
      <div className="flex h-screen">
        <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((c) => !c)} />
        <div className="flex flex-1 flex-col overflow-hidden">
          <TopBar />
          <main className="flex-1 overflow-auto px-4 py-3">{children}</main>
        </div>
      </div>
    </AuthGuard>
  );
}
