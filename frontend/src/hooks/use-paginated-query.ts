"use client";

import { useCallback, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api";

interface PaginatedResponse<T> {
  data: T[];
  meta: {
    next_cursor: string | null;
    has_more: boolean;
    total?: number | null;
  };
}

interface UsePaginatedQueryOptions {
  queryKey: readonly unknown[];
  path: string;
  pageSize?: number;
}

export function usePaginatedQuery<T>({ queryKey, path, pageSize = 20 }: UsePaginatedQueryOptions) {
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const previousPages = useRef<T[]>([]);

  const query = useQuery({
    queryKey: [...queryKey, cursor],
    refetchInterval: 30_000,
    queryFn: async () => {
      const params = new URLSearchParams();
      params.set("page_size", String(pageSize));
      if (cursor) params.set("cursor", cursor);
      return apiFetch<PaginatedResponse<T>>(`${path}?${params}`);
    },
  });

  const data = useMemo(() => {
    if (!query.data) return previousPages.current;
    return [...previousPages.current, ...query.data.data];
  }, [query.data]);

  const loadMore = useCallback(() => {
    if (query.data?.meta.next_cursor) {
      // Snapshot current accumulated data before loading next page
      previousPages.current = data;
      setCursor(query.data.meta.next_cursor);
    }
  }, [query.data, data]);

  const reset = useCallback(() => {
    previousPages.current = [];
    setCursor(undefined);
  }, []);

  return {
    data,
    total: query.data?.meta.total,
    hasMore: query.data?.meta.has_more ?? false,
    isLoading: query.isLoading,
    isFetching: query.isFetching,
    loadMore,
    reset,
    rawResponse: query.data,
  };
}
