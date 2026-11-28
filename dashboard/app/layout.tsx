import type { Metadata, Viewport } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import { SiteHeader, SiteFooter } from "./components/SiteChrome";
import { isProductionDeployment, siteUrl } from "@/lib/site-metadata";
import "./globals.css";

const description =
  "Check your website’s security configuration, understand findings, and verify your fixes with PatchProof, an open-source security tool.";
const socialImage = {
  url: "/og/patchproof-social.png",
  width: 1200,
  height: 630,
  alt: "PatchProof — an open-source website security configuration checker",
};

export const metadata: Metadata = {
  metadataBase: siteUrl,
  title: {
    default: "PatchProof — Website Security Configuration Checker",
    template: "%s | PatchProof",
  },
  description,
  applicationName: "PatchProof",
  authors: [{ name: "Fuad Hasan" }],
  creator: "Fuad Hasan",
  robots: {
    index: isProductionDeployment,
    follow: isProductionDeployment,
    googleBot: {
      index: isProductionDeployment,
      follow: isProductionDeployment,
      "max-image-preview": "large",
      "max-snippet": -1,
      "max-video-preview": -1,
    },
  },
  verification: process.env.GOOGLE_SITE_VERIFICATION
    ? { google: process.env.GOOGLE_SITE_VERIFICATION }
    : undefined,
  icons: {
    icon: [
      { url: "/favicon.svg", type: "image/svg+xml" },
      { url: "/favicon.ico", sizes: "any" },
      {
        url: "/favicon-16x16.png",
        type: "image/png",
        sizes: "16x16",
      },
      {
        url: "/favicon-32x32.png",
        type: "image/png",
        sizes: "32x32",
      },
      {
        url: "/icon-192.png",
        type: "image/png",
        sizes: "192x192",
      },
    ],
    apple: [{ url: "/apple-touch-icon.png", sizes: "180x180" }],
  },
  manifest: "/manifest.webmanifest",
  openGraph: {
    type: "website",
    url: siteUrl,
    siteName: "PatchProof",
    title: "PatchProof — Website Security Configuration Checker",
    description,
    images: [socialImage],
  },
  twitter: {
    card: "summary_large_image",
    title: "PatchProof — Website Security Configuration Checker",
    description,
    images: [socialImage],
  },
};

export const viewport: Viewport = {
  themeColor: "#087e55",
  colorScheme: "light dark",
};

const structuredData = [
  {
    "@context": "https://schema.org",
    "@type": "WebSite",
    name: "PatchProof",
    url: siteUrl.href,
    description,
    author: {
      "@type": "Person",
      name: "Fuad Hasan",
    },
  },
  {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: "PatchProof",
    description,
    url: siteUrl.href,
    applicationCategory: "SecurityApplication",
    operatingSystem: "Web",
    author: {
      "@type": "Person",
      name: "Fuad Hasan",
    },
    isAccessibleForFree: true,
    offers: {
      "@type": "Offer",
      price: "0",
      priceCurrency: "USD",
    },
  },
];

// Set the saved/system theme before first paint. This contains no user or server data.
const themeScript = `(function(){try{var t=localStorage.getItem('patchproof-theme');document.documentElement.dataset.theme=t==='dark'||(t!=='light'&&matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light'}catch(e){document.documentElement.dataset.theme=matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'}})()`;
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${GeistSans.variable} ${GeistMono.variable}`}
      suppressHydrationWarning
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>
        {structuredData.map((data) => (
          <script
            key={data["@type"]}
            type="application/ld+json"
            dangerouslySetInnerHTML={{
              __html: JSON.stringify(data).replace(/</g, "\\u003c"),
            }}
          />
        ))}
        <SiteHeader />
        {children}
        <SiteFooter />
      </body>
    </html>
  );
}
