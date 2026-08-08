import { defineComponents } from "blume";
import DarkOnlyHeader from "./components/DarkOnlyHeader.astro";

/**
 * Layout overrides for the Blume docs/marketing site.
 * Header: dark-only (no theme toggle; color mode locked to dark).
 */
export default defineComponents({
  layout: {
    Header: DarkOnlyHeader,
  },
});
