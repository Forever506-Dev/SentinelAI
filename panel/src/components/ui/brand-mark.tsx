import { cn } from "@/lib/utils";

interface BrandMarkProps {
  className?: string;
}

export function BrandMark({ className }: BrandMarkProps) {
  return (
    <svg
      viewBox="0 0 64 64"
      aria-hidden="true"
      className={cn("h-6 w-6", className)}
      fill="none"
    >
      <path
        d="M32 4 52 15.5v23L32 60 12 38.5v-23L32 4Z"
        fill="currentColor"
        fillOpacity="0.14"
        stroke="currentColor"
        strokeWidth="2.2"
      />
      <path
        d="M32 14 43 20.5v13L32 46 21 33.5v-13L32 14Z"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinejoin="round"
      />
      <circle cx="32" cy="30" r="4.5" fill="currentColor" />
      <path
        d="M24 39c2.8-3.1 5.8-4.7 8-4.7 2.3 0 5.3 1.6 8 4.7"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinecap="round"
      />
      <path
        d="M44.5 17.5 50 12"
        stroke="currentColor"
        strokeWidth="2.2"
        strokeLinecap="round"
      />
      <circle cx="52" cy="10" r="3" fill="currentColor" />
    </svg>
  );
}
