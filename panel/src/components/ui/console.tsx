import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface ConsolePanelProps {
  title?: string;
  subtitle?: string;
  icon?: ReactNode;
  action?: ReactNode;
  className?: string;
  children: ReactNode;
}

export function ConsolePanel({
  title,
  subtitle,
  icon,
  action,
  className,
  children,
}: ConsolePanelProps) {
  return (
    <section className={cn("console-panel", className)}>
      {(title || subtitle || action || icon) && (
        <header className="console-panel__header">
          <div className="flex min-w-0 items-start gap-3">
            {icon ? <div className="console-panel__icon">{icon}</div> : null}
            <div className="min-w-0">
              {title ? <h2 className="console-panel__title">{title}</h2> : null}
              {subtitle ? <p className="console-panel__subtitle">{subtitle}</p> : null}
            </div>
          </div>
          {action ? <div className="shrink-0">{action}</div> : null}
        </header>
      )}
      {children}
    </section>
  );
}

interface PageHeaderProps {
  eyebrow?: string;
  title: string;
  description: string;
  icon?: ReactNode;
  actions?: ReactNode;
  meta?: ReactNode;
  className?: string;
}

export function PageHeader({
  eyebrow,
  title,
  description,
  icon,
  actions,
  meta,
  className,
}: PageHeaderProps) {
  return (
    <section className={cn("page-header", className)}>
      <div className="flex min-w-0 items-start gap-4">
        {icon ? <div className="page-header__icon">{icon}</div> : null}
        <div className="min-w-0 flex-1">
          {eyebrow ? <p className="page-header__eyebrow">{eyebrow}</p> : null}
          <div className="flex flex-col gap-2 xl:flex-row xl:items-center xl:justify-between">
            <div>
              <h1 className="page-header__title">{title}</h1>
              <p className="page-header__description">{description}</p>
            </div>
            {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
          </div>
          {meta ? <div className="mt-4 flex flex-wrap items-center gap-2">{meta}</div> : null}
        </div>
      </div>
    </section>
  );
}

interface StatusPillProps {
  label: string;
  tone?: "default" | "success" | "warning" | "danger" | "info";
  icon?: ReactNode;
  pulse?: boolean;
  className?: string;
}

export function StatusPill({
  label,
  tone = "default",
  icon,
  pulse = false,
  className,
}: StatusPillProps) {
  return (
    <span
      className={cn(
        "status-pill",
        `status-pill--${tone}`,
        pulse && "status-pill--pulse",
        className,
      )}
    >
      {icon ? <span className="status-pill__icon">{icon}</span> : null}
      {label}
    </span>
  );
}
