import { Monitor } from "lucide-react";
import {
  siAndroid,
  siApple,
  siKalilinux,
  siLinux,
  siUbuntu,
  siArchlinux,
} from "simple-icons";
import { cn } from "@/lib/utils";

const WINDOWS_PATH = "M1 3.25 10.5 1.9v9.2H1V3.25Zm10.8-1.53L23 0v11.1H11.8V1.72ZM1 13.58h9.5v9.21L1 21.44V13.58Zm10.8 0H23V24l-11.2-1.58v-8.84Z";

type PlatformMeta = {
  title: string;
  path?: string;
};

function resolvePlatformMeta(osType?: string | null, osVersion?: string | null, hostname?: string | null): PlatformMeta {
  const source = `${osType ?? ""} ${osVersion ?? ""} ${hostname ?? ""}`.toLowerCase();

  if (source.includes("kali")) return { title: siKalilinux.title, path: siKalilinux.path };
  if (source.includes("windows")) return { title: "Windows", path: WINDOWS_PATH };
  if (source.includes("ubuntu")) return { title: siUbuntu.title, path: siUbuntu.path };
  if (source.includes("arch")) return { title: siArchlinux.title, path: siArchlinux.path };
  if (source.includes("android")) return { title: siAndroid.title, path: siAndroid.path };
  if (source.includes("mac") || source.includes("os x") || source.includes("darwin")) {
    return { title: siApple.title, path: siApple.path };
  }
  if (source.includes("linux")) return { title: siLinux.title, path: siLinux.path };

  return { title: "Endpoint" };
}

interface PlatformIconProps {
  osType?: string | null;
  osVersion?: string | null;
  hostname?: string | null;
  className?: string;
  tileClassName?: string;
}

export function PlatformIcon({
  osType,
  osVersion,
  hostname,
  className,
  tileClassName,
}: PlatformIconProps) {
  const platform = resolvePlatformMeta(osType, osVersion, hostname);

  return (
    <span
      className={cn(
        "flex h-10 w-10 items-center justify-center rounded-2xl border border-white/10 bg-black/20 text-slate-100 shadow-[0_18px_36px_-28px_rgba(0,0,0,0.95)]",
        tileClassName,
      )}
      title={platform.title}
      aria-label={platform.title}
    >
      {platform.path ? (
        <svg viewBox="0 0 24 24" className={cn("h-[18px] w-[18px]", className)} fill="currentColor" aria-hidden="true">
          <path d={platform.path} />
        </svg>
      ) : (
        <Monitor className={cn("h-[18px] w-[18px]", className)} aria-hidden="true" />
      )}
    </span>
  );
}
