"use client";

import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/skeleton";
import { EmptyState } from "@/components/empty-state";
import { Inbox, ChevronLeft, ChevronRight, ArrowUp, ArrowDown, ArrowUpDown } from "lucide-react";
import type { Column } from "@/components/data-table";

export interface SortableColumn<T> extends Column<T> {
  sortKey?: string;
}

interface PagedTableProps<T> {
  columns: SortableColumn<T>[];
  data: T[];
  page: number;
  totalPages?: number;
  total?: number;
  hasNext: boolean;
  hasPrev: boolean;
  onNext: () => void;
  onPrev: () => void;
  isLoading?: boolean;
  pageSize: number;
  onRowClick?: (row: T) => void;
  keyExtractor: (row: T) => string;
  emptyTitle?: string;
  emptyDescription?: string;
  sortBy?: string;
  sortDir?: "asc" | "desc";
  onSort?: (key: string) => void;
}

export function PagedTable<T>({
  columns,
  data,
  page,
  totalPages,
  total,
  hasNext,
  hasPrev,
  onNext,
  onPrev,
  isLoading,
  pageSize,
  onRowClick,
  keyExtractor,
  emptyTitle = "No data found",
  emptyDescription = "There are no records to display yet.",
  sortBy,
  sortDir,
  onSort,
}: PagedTableProps<T>) {
  const showingFrom = page * pageSize + 1;
  const showingTo = page * pageSize + data.length;

  return (
    <div>
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            {columns.map((col) => (
              <TableHead key={col.header} className={col.className}>
                {col.sortKey && onSort ? (
                  <button
                    type="button"
                    className="inline-flex items-center gap-1 hover:text-foreground transition-colors -ml-1 px-1 py-0.5 rounded"
                    onClick={() => onSort(col.sortKey!)}
                  >
                    {col.header}
                    {sortBy === col.sortKey ? (
                      sortDir === "asc" ? (
                        <ArrowUp className="h-3 w-3" />
                      ) : (
                        <ArrowDown className="h-3 w-3" />
                      )
                    ) : (
                      <ArrowUpDown className="h-3 w-3 opacity-40" />
                    )}
                  </button>
                ) : (
                  col.header
                )}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {isLoading && data.length === 0 ? (
            Array.from({ length: pageSize }).map((_, i) => (
              <TableRow key={i}>
                {columns.map((col) => (
                  <TableCell key={col.header} className={col.className}>
                    <Skeleton className="h-4 w-3/4" />
                  </TableCell>
                ))}
              </TableRow>
            ))
          ) : data.length === 0 ? (
            <TableRow className="hover:bg-transparent">
              <TableCell colSpan={columns.length} className="p-0">
                <EmptyState
                  icon={Inbox}
                  title={emptyTitle}
                  description={emptyDescription}
                />
              </TableCell>
            </TableRow>
          ) : (
            data.map((row) => (
              <TableRow
                key={keyExtractor(row)}
                className={onRowClick ? "cursor-pointer" : ""}
                onClick={() => onRowClick?.(row)}
              >
                {columns.map((col) => (
                  <TableCell key={col.header} className={col.className}>
                    {col.accessor(row)}
                  </TableCell>
                ))}
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>

      {(hasPrev || hasNext || (total != null && total > 0)) && (
        <div className="flex items-center justify-between pt-2">
          <span className="text-[11px] text-muted-foreground">
            {total != null
              ? `${showingFrom}–${showingTo} of ${total}`
              : `Page ${page + 1}`}
          </span>
          <div className="flex items-center gap-1">
            <Button
              variant="outline"
              size="sm"
              onClick={onPrev}
              disabled={!hasPrev || isLoading}
              className="h-7 w-7 p-0"
            >
              <ChevronLeft className="h-3.5 w-3.5" />
            </Button>
            {totalPages != null && (
              <span className="text-[11px] text-muted-foreground px-1.5">
                {page + 1} / {totalPages}
              </span>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={onNext}
              disabled={!hasNext || isLoading}
              className="h-7 w-7 p-0"
            >
              <ChevronRight className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
