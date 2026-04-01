import type { ReactNode } from "react";
import { Radar } from "lucide-react";
import { BrandMark } from "@/components/ui/brand-mark";

interface AuthShellProps {
  eyebrow: string;
  title: string;
  description: string;
  children: ReactNode;
  footer?: ReactNode;
}

export function AuthShell({
  eyebrow,
  title,
  description,
  children,
  footer,
}: AuthShellProps) {
  return (
    <div className="auth-shell">
      <div className="auth-shell__backdrop" />
      <div className="auth-shell__content">
        <div className="auth-shell__intro">
          <div className="inline-flex items-center gap-3 rounded-full border border-white/10 bg-white/[0.05] px-4 py-2 text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-200/90">
            <Radar className="h-3.5 w-3.5" />
            Tactical Operator Console
          </div>
          <div className="mt-6 flex items-center gap-4">
            <div className="auth-shell__brand-mark">
              <BrandMark className="h-7 w-7 text-white" />
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.28em] text-slate-300/80">{eyebrow}</p>
              <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white sm:text-4xl">{title}</h1>
            </div>
          </div>
          <p className="mt-5 max-w-xl text-sm leading-7 text-slate-300/75 sm:text-base">
            {description}
          </p>
          <div className="mt-8 grid gap-3 text-xs text-slate-400 sm:grid-cols-3">
            <div className="auth-shell__signal-tile">
              <span className="auth-shell__signal-label">Threat-aware UI</span>
              <span className="auth-shell__signal-value">Layered command surfaces</span>
            </div>
            <div className="auth-shell__signal-tile">
              <span className="auth-shell__signal-label">Response posture</span>
              <span className="auth-shell__signal-value">Fast, verified access</span>
            </div>
            <div className="auth-shell__signal-tile">
              <span className="auth-shell__signal-label">Operator access</span>
              <span className="auth-shell__signal-value">Secure by default</span>
            </div>
          </div>
        </div>

        <div className="auth-shell__panel">{children}</div>
      </div>

      {footer ? <div className="auth-shell__footer">{footer}</div> : null}
    </div>
  );
}
