"use client";
import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import {
  ShieldCheck,
  GitFork,
  BookOpen,
  Sun,
  Moon,
  Menu,
  X,
} from "lucide-react";

export const repository = "https://github.com/fuadhasandev/patchproof";
export function SiteHeader() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [dark, setDark] = useState(false);
  useEffect(() => {
    const media = matchMedia("(prefers-color-scheme: dark)");
    const sync = () => {
      let saved: string | null = null;
      try {
        saved = localStorage.getItem("patchproof-theme");
      } catch {}
      const next = saved === "dark" || (saved !== "light" && media.matches);
      document.documentElement.dataset.theme = next ? "dark" : "light";
      setDark(next);
    };
    sync();
    media.addEventListener("change", sync);
    window.addEventListener("storage", sync);
    return () => {
      media.removeEventListener("change", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);
  function toggleTheme() {
    const next = !dark;
    setDark(next);
    document.documentElement.dataset.theme = next ? "dark" : "light";
    try {
      localStorage.setItem("patchproof-theme", next ? "dark" : "light");
    } catch {}
  }
  return (
    <header className="site-header">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <div className="nav-shell">
        <a className="brand" href="/" aria-label="PatchProof home">
          <span className="brand-mark">
            <ShieldCheck size={23} strokeWidth={1.8} />
          </span>
          PatchProof
        </a>
        <nav
          id="primary-nav"
          className={open ? "primary-nav is-open" : "primary-nav"}
          aria-label="Main navigation"
        >
          <a href="/" aria-current={pathname === "/" ? "page" : undefined}>
            Website checker
          </a>
          <a
            href="/advanced"
            aria-current={pathname === "/advanced" ? "page" : undefined}
          >
            Advanced
          </a>
          <a href={`${repository}/blob/main/README.md`}>
            <BookOpen size={16} />
            Documentation
          </a>
        </nav>
        <div className="nav-actions">
          <a className="github-link" href={repository}>
            <GitFork size={18} />
            <span>GitHub</span>
          </a>
          <span className="nav-divider" />
          <button
            className="icon-button theme-toggle"
            onClick={toggleTheme}
            aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}
          >
            <Sun className="sun-icon" size={19} />
            <Moon className="moon-icon" size={19} />
          </button>
          <button
            className="icon-button menu-toggle"
            aria-label={open ? "Close navigation" : "Open navigation"}
            aria-expanded={open}
            aria-controls="primary-nav"
            onClick={() => setOpen(!open)}
          >
            {open ? <X size={21} /> : <Menu size={21} />}
          </button>
        </div>
      </div>
    </header>
  );
}
export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div>
        <a className="brand footer-brand" href="/">
          <ShieldCheck size={20} />
          PatchProof
        </a>
        <span>Focused checks. Clear evidence.</span>
      </div>
      <nav aria-label="Footer navigation">
        <a href={`${repository}/blob/main/README.md`}>Documentation</a>
        <a href={repository}>Source code</a>
        <a href={`${repository}/blob/main/SECURITY.md`}>Security</a>
      </nav>
    </footer>
  );
}
