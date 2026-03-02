"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";

export default function Home() {
  const router = useRouter();
  useEffect(() => {
    if (api.getToken()) {
      router.push("/dashboard");
    } else {
      router.push("/login");
    }
  }, [router]);
  return null;
}
