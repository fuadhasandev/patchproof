import type { MetadataRoute } from "next";
import { isProductionDeployment, siteUrl } from "@/lib/site-metadata";

export default function sitemap(): MetadataRoute.Sitemap {
  if (!isProductionDeployment) return [];

  return [
    {
      url: siteUrl.href,
      priority: 1,
      changeFrequency: "monthly",
    },
  ];
}
