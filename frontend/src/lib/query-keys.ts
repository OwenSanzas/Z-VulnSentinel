export const queryKeys = {
  dashboard: ["dashboard"] as const,
  libraries: {
    all: ["libraries"] as const,
    list: (cursor?: string) => ["libraries", "list", cursor] as const,
    detail: (id: string) => ["libraries", id] as const,
  },
  projects: {
    all: ["projects"] as const,
    list: (cursor?: string) => ["projects", "list", cursor] as const,
    detail: (id: string) => ["projects", id] as const,
    vulns: (id: string, cursor?: string) =>
      ["projects", id, "vulns", cursor] as const,
    deps: (id: string, cursor?: string) =>
      ["projects", id, "deps", cursor] as const,
  },
  events: {
    all: ["events"] as const,
    list: (cursor?: string, libraryId?: string) =>
      ["events", "list", cursor, libraryId] as const,
    detail: (id: string) => ["events", id] as const,
  },
  upstreamVulns: {
    all: ["upstream-vulns"] as const,
    list: (cursor?: string, libraryId?: string) =>
      ["upstream-vulns", "list", cursor, libraryId] as const,
    detail: (id: string) => ["upstream-vulns", id] as const,
  },
  clientVulns: {
    all: ["client-vulns"] as const,
    list: (filters?: Record<string, string | undefined>) =>
      ["client-vulns", "list", filters] as const,
    detail: (id: string) => ["client-vulns", id] as const,
    stats: (projectId?: string) =>
      ["client-vulns", "stats", projectId] as const,
  },
};
