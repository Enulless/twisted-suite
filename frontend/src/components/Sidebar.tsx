import { NavLink } from "react-router-dom";
import {
  Briefcase,
  Command,
  Container,
  GraduationCap,
  LogOut,
  ScrollText,
  Server,
  Shield,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { ThemeToggle } from "./ThemeToggle";

const NAV = [
  { to: "/", label: "Engagements", icon: Briefcase, end: true },
  { to: "/workers", label: "Workers", icon: Server },
  { to: "/labs", label: "Labs", icon: Container },
  { to: "/training", label: "Training", icon: GraduationCap },
  { to: "/procedures", label: "Procedures", icon: ScrollText },
];

export function Sidebar() {
  return (
    <aside className="flex h-screen w-60 flex-col border-r border-border bg-card">
      <div className="flex items-center gap-2 px-5 py-4 border-b border-border">
        <Shield className="h-5 w-5 text-primary" />
        <div className="flex flex-col leading-tight">
          <span className="text-sm font-semibold tracking-tight">Twisted</span>
          <span className="text-[10px] text-muted-foreground uppercase tracking-widest">
            Pen Testing Suite
          </span>
        </div>
      </div>
      <nav className="flex-1 px-2 py-3 space-y-0.5">
        {NAV.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm",
                "transition-colors",
                isActive
                  ? "bg-accent text-accent-foreground font-medium"
                  : "text-muted-foreground hover:bg-accent hover:text-foreground",
              )
            }
          >
            <Icon className="h-4 w-4" />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>
      <div className="border-t border-border p-2 space-y-1">
        <div className="flex items-center justify-between px-1">
          <span className="text-[10px] uppercase tracking-wider text-muted-foreground px-2">
            Theme
          </span>
          <ThemeToggle />
        </div>
        <div className="flex items-center justify-between px-3 py-1.5 rounded-md
                        text-xs text-muted-foreground border border-dashed border-border/50">
          <span className="flex items-center gap-1.5">
            <Command className="h-3 w-3" /> palette
          </span>
          <kbd className="text-[9px] border border-border rounded px-1">⌘K</kbd>
        </div>
        <a
          href="/logout"
          className="flex items-center gap-3 rounded-md px-3 py-2 text-sm
                     text-muted-foreground hover:bg-accent hover:text-foreground
                     transition-colors"
        >
          <LogOut className="h-4 w-4" />
          <span>Sign out</span>
        </a>
      </div>
    </aside>
  );
}
