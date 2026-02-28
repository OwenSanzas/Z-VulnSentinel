"use client";

import { useRouter } from "next/navigation";
import { useCallback } from "react";
import { useAuthStore } from "@/lib/auth-store";

export function useAuth() {
  const router = useRouter();
  const { isAuthenticated, logout: storeLogout } = useAuthStore();

  const logout = useCallback(() => {
    storeLogout();
    router.push("/login");
  }, [storeLogout, router]);

  return { isAuthenticated, logout };
}
