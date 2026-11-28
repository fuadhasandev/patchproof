import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import { SiteHeader, SiteFooter } from "./components/SiteChrome";
import "./globals.css";
export const metadata: Metadata = {
  title: "PatchProof · Website security checker",
  description:
    "Understand your website’s security configuration. Inspect evidence, make a fix, and verify what changed with open-source checks.",
};
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
        <SiteHeader />
        {children}
        <SiteFooter />
      </body>
    </html>
  );
}
