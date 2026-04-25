import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Briefcase,
  Container,
  GraduationCap,
  Plus,
  Search,
  Server,
  ShieldOff,
} from "lucide-react";
import { listEngagements } from "@/api/engagements";
import { Dialog, DialogContent } from "./ui/dialog";
import { cn } from "@/lib/utils";

interface Item {
  id: string;
  label: string;
  hint?: string;
  icon: typeof Briefcase;
  action: () => void;
  keywords: string;
}

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const navigate = useNavigate();
  const { data: engagements } = useQuery({
    queryKey: ["engagements"],
    queryFn: listEngagements,
  });

  // ⌘K / Ctrl+K toggle
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      } else if (e.key === "Escape") {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  const close = () => {
    setOpen(false);
    setQuery("");
  };

  const items: Item[] = [
    {
      id: "nav-engagements",
      label: "Go to Engagements",
      icon: Briefcase,
      action: () => navigate("/"),
      keywords: "engagements home list",
    },
    {
      id: "nav-workers",
      label: "Go to Workers",
      icon: Server,
      action: () => navigate("/workers"),
      keywords: "workers daemons",
    },
    {
      id: "nav-labs",
      label: "Go to Labs",
      icon: Container,
      action: () => navigate("/labs"),
      keywords: "labs docker dvwa juice metasploit wordpress",
    },
    {
      id: "nav-training",
      label: "Go to Training",
      icon: GraduationCap,
      action: () => navigate("/training"),
      keywords: "training lessons quizzes",
    },
    {
      id: "new-engagement",
      label: "Create new engagement",
      hint: "Wizard",
      icon: Plus,
      action: () => navigate("/engagements/new"),
      keywords: "new engagement create wizard",
    },
    ...(engagements ?? []).flatMap((e) => [
      {
        id: `eng-${e.id}`,
        label: `Open: ${e.client}`,
        hint: e.primary_domain ?? "",
        icon: Briefcase,
        action: () => navigate(`/engagements/${e.id}`),
        keywords: `${e.client} ${e.primary_domain ?? ""} engagement`.toLowerCase(),
      },
      {
        id: `eng-${e.id}-tooling`,
        label: `${e.client}: tool policy (RoE)`,
        hint: "Tooling",
        icon: ShieldOff,
        action: () => navigate(`/engagements/${e.id}/tooling`),
        keywords: `${e.client} tooling roe policy`.toLowerCase(),
      },
    ]),
  ];

  const filtered = query
    ? items.filter((i) =>
        i.label.toLowerCase().includes(query.toLowerCase()) ||
        i.keywords.includes(query.toLowerCase()),
      )
    : items;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="p-0 max-w-xl">
        <div className="flex items-center gap-2 border-b border-border px-3">
          <Search className="h-4 w-4 text-muted-foreground" />
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Type a command or search…"
            className="flex-1 bg-transparent py-3 text-sm outline-none placeholder:text-muted-foreground"
            onKeyDown={(e) => {
              if (e.key === "Enter" && filtered.length > 0) {
                filtered[0].action();
                close();
              }
            }}
          />
          <kbd className="text-[10px] text-muted-foreground border border-border rounded px-1.5 py-0.5">
            ESC
          </kbd>
        </div>
        <div className="max-h-80 overflow-y-auto p-1">
          {filtered.length === 0 && (
            <div className="text-sm text-muted-foreground px-3 py-8 text-center">
              No matches.
            </div>
          )}
          {filtered.map((item, i) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => { item.action(); close(); }}
                className={cn(
                  "w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm",
                  "hover:bg-accent transition-colors",
                  i === 0 && query && "bg-accent",
                )}
              >
                <Icon className="h-4 w-4 text-muted-foreground" />
                <span className="flex-1 text-left">{item.label}</span>
                {item.hint && (
                  <span className="text-xs text-muted-foreground">
                    {item.hint}
                  </span>
                )}
              </button>
            );
          })}
        </div>
        <div className="border-t border-border px-3 py-2 flex items-center gap-3 text-[10px] text-muted-foreground">
          <span>
            <kbd className="border border-border rounded px-1">⏎</kbd> select
          </span>
          <span>
            <kbd className="border border-border rounded px-1">⌘K</kbd> toggle
          </span>
        </div>
      </DialogContent>
    </Dialog>
  );
}
