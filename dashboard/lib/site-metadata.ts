export const siteUrl = new URL(
  process.env.NEXT_PUBLIC_SITE_URL || "https://patchproof-teal.vercel.app",
);

export const isProductionDeployment =
  process.env.PATCHPROOF_DEPLOYMENT_ENV === "production";
