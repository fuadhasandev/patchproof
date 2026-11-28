import type { MetadataRoute } from "next";
import { siteUrl } from "@/lib/site-metadata";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: "/",
      disallow: ["/api/", "/advanced", "/reports/", "/workbench/"],
    },
    sitemap: new URL("/sitemap.xml", siteUrl).href,
  };
}
