// The site is served from GitHub Pages at https://aabhimittal.github.io/reverse-engineer/.
// /demo/ (generated lab bench) and /docs/ (mdBook) are copied into dist by the Pages workflow.
import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://aabhimittal.github.io",
  base: "/reverse-engineer",
  trailingSlash: "ignore",
  build: { format: "directory" },
});
