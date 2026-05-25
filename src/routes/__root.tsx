import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  Outlet,
  Link,
  createRootRouteWithContext,
  useRouter,
  HeadContent,
  Scripts,
} from "@tanstack/react-router";
import { useState } from "react";

import appCss from "../styles.css?url";
import { Sidebar } from "@/components/dfas/Sidebar";
import { TopBar } from "@/components/dfas/TopBar";

function NotFoundComponent() {
  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="glass rounded-2xl p-10 text-center max-w-md">
        <div className="font-mono text-cyan text-sm mb-2">ERR_404 · NOT_FOUND</div>
        <h1 className="text-6xl font-bold glow-text-cyan">404</h1>
        <h2 className="mt-3 text-lg">المورد غير موجود</h2>
        <p className="mt-2 text-sm text-muted-foreground">المسار المطلوب لا يوجد ضمن نظام DFAS.</p>
        <Link to="/" className="inline-flex mt-6 px-5 py-2.5 rounded-lg bg-primary text-primary-foreground font-medium glow-cyan">
          العودة للرئيسية
        </Link>
      </div>
    </div>
  );
}

function ErrorComponent({ error, reset }: { error: Error; reset: () => void }) {
  console.error(error);
  const router = useRouter();
  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="glass rounded-2xl p-10 text-center max-w-md">
        <div className="font-mono text-critical text-sm mb-2">ERR_RUNTIME</div>
        <h1 className="text-xl font-semibold">تعذّر تحميل الصفحة</h1>
        <p className="mt-2 text-sm text-muted-foreground">حدث خطأ في النظام. يمكنك إعادة المحاولة.</p>
        <div className="mt-6 flex justify-center gap-2">
          <button onClick={() => { router.invalidate(); reset(); }} className="px-4 py-2 rounded-lg bg-primary text-primary-foreground">إعادة المحاولة</button>
          <a href="/" className="px-4 py-2 rounded-lg border border-border">الرئيسية</a>
        </div>
      </div>
    </div>
  );
}

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { title: "DFAS v2 — نظام التحليل الجنائي الرقمي" },
      { name: "description", content: "DFAS — منصة تحليل جنائي رقمي وتعليم الأمن السيبراني." },
      { name: "author", content: "DFAS" },
      { property: "og:title", content: "DFAS v2 — Digital Forensics Analysis System" },
      { property: "og:description", content: "Arabic-first cybersecurity forensics dashboard." },
      { property: "og:type", content: "website" },
    ],
    links: [{ rel: "stylesheet", href: appCss }],
  }),
  shellComponent: RootShell,
  component: RootComponent,
  notFoundComponent: NotFoundComponent,
  errorComponent: ErrorComponent,
});

function RootShell({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ar" dir="rtl" className="dark">
      <head><HeadContent /></head>
      <body>{children}<Scripts /></body>
    </html>
  );
}

function RootComponent() {
  const { queryClient } = Route.useRouteContext();
  const [open, setOpen] = useState(false);

  return (
    <QueryClientProvider client={queryClient}>
      <div className="flex flex-row-reverse min-h-screen">
        <Sidebar open={open} onClose={() => setOpen(false)} />
        <div className="flex-1 flex flex-col min-w-0 relative z-10">
          <TopBar onMenu={() => setOpen(true)} />
          <main className="flex-1"><Outlet /></main>
          <footer className="px-6 py-4 text-center text-[11px] text-muted-foreground font-mono border-t border-border">
            DFAS v2.0 · ISO/IEC 27037 · NIST 800-86 · RFC 3227 · TLP:AMBER
          </footer>
        </div>
      </div>
    </QueryClientProvider>
  );
}
