// Theme bootstrap for the root layout.
//
// Loaded synchronously (not deferred) from <head> so <html data-theme> is set
// before the stylesheet paints — otherwise a user with an explicit theme sees a
// flash of the default one. It lives in a static file rather than an inline
// <script> because the production Content-Security-Policy is `script-src 'self'`
// (see lib/accela_imageboard_web/plugs/secure_headers.ex), and it is a separate
// esbuild entry point (see config/config.exs) so it does not wait for the
// LiveView bundle.
//
// The toggle buttons dispatch `phx:set-theme` with `data-phx-theme`, and the
// `storage` listener keeps several tabs in sync.
(() => {
  const systemTheme = () =>
    matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";

  const setTheme = (theme) => {
    if (theme === "system") {
      localStorage.removeItem("phx:theme");
      document.documentElement.setAttribute("data-theme", systemTheme());
      document.documentElement.setAttribute("data-theme-source", "system");
    } else {
      localStorage.setItem("phx:theme", theme);
      document.documentElement.setAttribute("data-theme", theme);
      document.documentElement.setAttribute("data-theme-source", "user");
    }
  };

  if (!document.documentElement.hasAttribute("data-theme")) {
    setTheme(localStorage.getItem("phx:theme") || "system");
  }

  window.addEventListener("storage", (event) => {
    if (event.key === "phx:theme") setTheme(event.newValue || "system");
  });

  window.addEventListener("phx:set-theme", (event) => {
    setTheme(event.target.dataset.phxTheme);
  });

  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (document.documentElement.getAttribute("data-theme-source") === "system") {
      document.documentElement.setAttribute("data-theme", systemTheme());
    }
  });
})();
