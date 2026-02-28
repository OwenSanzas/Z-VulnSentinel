"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch, ApiError } from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import Link from "next/link";
import { ArrowLeft, Loader2 } from "lucide-react";

interface CreateProjectResponse {
  id: string;
  name: string;
  repo_url: string;
}

/** Extract "org/repo" from a GitHub URL, or null if invalid. */
function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  const m = url.trim().match(/github\.com\/([^/]+)\/([^/.\s]+)/);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

export default function NewProjectPage() {
  const router = useRouter();
  const queryClient = useQueryClient();

  const [repoUrl, setRepoUrl] = useState("");
  const [name, setName] = useState("");
  const [organization, setOrganization] = useState("");
  const [contact, setContact] = useState("");
  const [defaultBranch, setDefaultBranch] = useState("main");
  const [autoSyncDeps, setAutoSyncDeps] = useState(true);
  const [error, setError] = useState("");

  // Branch fetching
  const [branches, setBranches] = useState<string[]>([]);
  const [branchesLoading, setBranchesLoading] = useState(false);
  const [branchesError, setBranchesError] = useState("");

  const fetchBranches = useCallback(async (url: string) => {
    const parsed = parseGitHubUrl(url);
    if (!parsed) {
      setBranches([]);
      return;
    }

    setBranchesLoading(true);
    setBranchesError("");
    try {
      const result = await apiFetch<string[]>(
        `/api/v1/projects/github/branches?repo_url=${encodeURIComponent(url.trim())}`
      );
      setBranches(result);
      // Auto-select default branch
      if (result.length > 0) {
        const preferred = result.includes("main")
          ? "main"
          : result.includes("master")
            ? "master"
            : result[0];
        setDefaultBranch(preferred);
      }
    } catch {
      setBranchesError("Failed to fetch branches");
      setBranches([]);
    } finally {
      setBranchesLoading(false);
    }
  }, []);

  // Auto-fill name from URL and fetch branches on blur
  const handleRepoUrlBlur = useCallback(() => {
    const parsed = parseGitHubUrl(repoUrl);
    if (parsed) {
      if (!name) setName(parsed.repo);
      if (!organization) setOrganization(parsed.owner);
      fetchBranches(repoUrl);
    }
  }, [repoUrl, name, organization, fetchBranches]);

  const mutation = useMutation({
    mutationFn: () =>
      apiFetch<CreateProjectResponse>("/api/v1/projects/", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          repo_url: repoUrl.trim(),
          organization: organization.trim() || null,
          contact: contact.trim() || null,
          default_branch: defaultBranch,
          auto_sync_deps: autoSyncDeps,
        }),
      }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.projects.all });
      router.push(`/project/${data.id}`);
    },
    onError: (err) => {
      if (err instanceof ApiError && err.status === 409) {
        setError("Project with this URL already exists");
      } else {
        setError(err.message || "Failed to create project");
      }
    },
  });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    mutation.mutate();
  }

  return (
    <div className="space-y-3">
      <PageHeader
        title="New Project"
        description="Register a project for vulnerability monitoring"
        actions={
          <Link
            href="/projects"
            className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <ArrowLeft className="h-3 w-3" />
            Back
          </Link>
        }
      />

      <Card className="max-w-lg">
        <CardHeader>
          <CardTitle>Project Details</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="repo_url" className="text-xs">
                Repository URL <span className="text-destructive">*</span>
              </Label>
              <Input
                id="repo_url"
                placeholder="https://github.com/org/repo"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                onBlur={handleRepoUrlBlur}
                required
                autoFocus
                className="h-8 text-sm"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="name" className="text-xs">
                Project Name <span className="text-destructive">*</span>
              </Label>
              <Input
                id="name"
                placeholder="my-project"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="h-8 text-sm"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="organization" className="text-xs">
                Organization
              </Label>
              <Input
                id="organization"
                placeholder="Optional"
                value={organization}
                onChange={(e) => setOrganization(e.target.value)}
                className="h-8 text-sm"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="contact" className="text-xs">
                Contact
              </Label>
              <Input
                id="contact"
                placeholder="Optional"
                value={contact}
                onChange={(e) => setContact(e.target.value)}
                className="h-8 text-sm"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="default_branch" className="text-xs">
                Default Branch
                {branchesLoading && (
                  <Loader2 className="inline h-3 w-3 ml-1 animate-spin text-muted-foreground" />
                )}
              </Label>
              {branches.length > 0 ? (
                <select
                  id="default_branch"
                  value={defaultBranch}
                  onChange={(e) => setDefaultBranch(e.target.value)}
                  className="flex h-8 w-full rounded-md border border-input bg-background px-3 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                >
                  {branches.map((b) => (
                    <option key={b} value={b}>
                      {b}
                    </option>
                  ))}
                </select>
              ) : (
                <Input
                  id="default_branch"
                  value={defaultBranch}
                  onChange={(e) => setDefaultBranch(e.target.value)}
                  className="h-8 text-sm"
                />
              )}
              {branchesError && (
                <p className="text-xs text-muted-foreground">{branchesError}</p>
              )}
            </div>

            <div className="flex items-center gap-2">
              <input
                id="auto_sync_deps"
                type="checkbox"
                checked={autoSyncDeps}
                onChange={(e) => setAutoSyncDeps(e.target.checked)}
                className="h-3.5 w-3.5 rounded border-input accent-primary"
              />
              <Label htmlFor="auto_sync_deps" className="text-xs cursor-pointer">
                Auto-sync dependencies
              </Label>
            </div>

            {error && <p className="text-xs text-destructive">{error}</p>}

            <Button
              type="submit"
              className="w-full h-8 text-xs"
              disabled={mutation.isPending}
            >
              {mutation.isPending ? "Creating..." : "Create Project"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
