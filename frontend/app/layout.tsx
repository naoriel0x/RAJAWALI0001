import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import Sidebar from "../components/ui/Sidebar";
import { APP_DESCRIPTION, APP_NAME } from "@/lib/constants";
import Favicon from "./favicon.png";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono" });

export const metadata: Metadata = {
  title: APP_NAME,
  description: APP_DESCRIPTION,
  icons: {
    icon: [
      { url: Favicon.src, sizes: "32x32", type: "image/png" },
      { url: Favicon.src, sizes: "48x48", type: "image/png" },
    ],
    shortcut: Favicon.src,
    apple: Favicon.src,
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className={`${inter.variable} ${mono.variable} min-h-screen bg-[#0a0a0a] text-[#c9d1d9] antialiased`}>
        <Sidebar />
        <main className="min-h-screen flex-1 pb-24 lg:ml-64 lg:pb-0">
          {children}
        </main>
      </body>
    </html>
  );
}