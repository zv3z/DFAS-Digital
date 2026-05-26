import { QueryClient } from "@tanstack/react-query";
import { createRouter } from "@tanstack/react-router";
import { routeTree } from "./routeTree.gen";

export const getRouter = () => {
  const queryClient = new QueryClient();

  // BASE_URL is injected by Vite from the `base` config option.
  // In production GitHub Pages build it equals '/DFAS-Digital/'.
  // Strip the trailing slash so TanStack Router gets '/DFAS-Digital'.
  const basepath =
    (import.meta.env.BASE_URL ?? "/").replace(/\/$/, "") || "/";

  const router = createRouter({
    routeTree,
    context: { queryClient },
    scrollRestoration: true,
    defaultPreloadStaleTime: 0,
    basepath,
  });

  return router;
};
