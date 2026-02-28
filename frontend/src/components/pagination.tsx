"use client";

import { Button } from "@/components/ui/button";
import { ChevronRight, Loader2 } from "lucide-react";

interface PaginationProps {
  hasMore: boolean;
  onLoadMore: () => void;
  isLoading?: boolean;
}

export function Pagination({ hasMore, onLoadMore, isLoading }: PaginationProps) {
  if (!hasMore) return null;
  return (
    <div className="flex justify-center pt-2">
      <Button
        variant="ghost"
        size="sm"
        onClick={onLoadMore}
        disabled={isLoading}
        className="text-xs text-muted-foreground h-7"
      >
        {isLoading ? (
          <>
            <Loader2 className="mr-1 h-3 w-3 animate-spin" />
            Loading...
          </>
        ) : (
          <>
            Load more
            <ChevronRight className="ml-0.5 h-3 w-3" />
          </>
        )}
      </Button>
    </div>
  );
}
