"use client";

import { useCallback, useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api";

interface PaginatedResponse<T> {
  data: T[];
  meta: {
    next_cursor: string | null;
    has_more: boolean;
    total?: number | null;
    page?: number | null;
    total_pages?: number | null;
  };
}

interface UsePagedQueryOptions {
  queryKey: readonly unknown[];
  path: string;
  pageSize?: number;
  params?: Record<string, string>;
}

/**
 * Offset-based pagination with sorting/filtering support.
 * Sends `page` and optional extra params as query string parameters.
 */
export function usePagedQuery<T>({
  queryKey,
  path,
  pageSize = 20,
  params,
}: UsePagedQueryOptions) {
  const [page, setPage] = useState(0);

  // Reset to first page when params change
  const paramsKey = params ? JSON.stringify(params) : "";
  useEffect(() => {
    setPage(0);
  }, [paramsKey]);

  const query = useQuery({
    queryKey: [...queryKey, "paged", page, paramsKey],
    refetchInterval: 30_000,
    queryFn: async () => {
      const urlParams = new URLSearchParams();
      urlParams.set("page", String(page));
      urlParams.set("page_size", String(pageSize));
      if (params) {
        for (const [k, v] of Object.entries(params)) {
          if (v) urlParams.set(k, v);
        }
      }
      return apiFetch<PaginatedResponse<T>>(`${path}?${urlParams}`);
    },
  });

  const hasNext = query.data?.meta.has_more ?? false;
  const hasPrev = page > 0;

  const nextPage = useCallback(() => {
    if (hasNext) setPage((p) => p + 1);
  }, [hasNext]);

  const prevPage = useCallback(() => {
    if (hasPrev) setPage((p) => p - 1);
  }, [hasPrev]);

  const total = query.data?.meta.total ?? undefined;
  const totalPages = query.data?.meta.total_pages ?? (total != null ? Math.ceil(total / pageSize) : undefined);

  return {
    data: query.data?.data ?? [],
    page,
    totalPages,
    total,
    hasNext,
    hasPrev,
    nextPage,
    prevPage,
    isLoading: query.isLoading,
    isFetching: query.isFetching,
    pageSize,
  };
}
