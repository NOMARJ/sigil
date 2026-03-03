import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import { QueryProvider } from '@/providers/QueryProvider';
import { ToastProvider } from '@/components/ui/Toast';
import { Header } from '@/components/layout/Header';
import { Footer } from '@/components/layout/Footer';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'Sigil Forge - AI Agent Tool Discovery',
  description: 'Discover, evaluate, and deploy AI agent tools with confidence. Find MCP servers, Claude skills, and verified agent tooling.',
  keywords: [
    'AI agents',
    'MCP server',
    'Claude skills',
    'AI tools',
    'agent development',
    'tool discovery',
    'security scanning',
    'trust scores'
  ],
  authors: [{ name: 'Sigil Security' }],
  creator: 'Sigil Security',
  publisher: 'Sigil Security',
  formatDetection: {
    email: false,
    address: false,
    telephone: false,
  },
  metadataBase: new URL('https://forge.sigilsec.ai'),
  alternates: {
    canonical: '/',
  },
  openGraph: {
    title: 'Sigil Forge - AI Agent Tool Discovery',
    description: 'Discover, evaluate, and deploy AI agent tools with confidence.',
    url: 'https://forge.sigilsec.ai',
    siteName: 'Sigil Forge',
    locale: 'en_US',
    type: 'website',
    images: [
      {
        url: '/og-image.png',
        width: 1200,
        height: 630,
        alt: 'Sigil Forge - AI Agent Tool Discovery',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Sigil Forge - AI Agent Tool Discovery',
    description: 'Discover, evaluate, and deploy AI agent tools with confidence.',
    creator: '@sigilsec',
    images: ['/og-image.png'],
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
  verification: {
    google: process.env.NEXT_PUBLIC_GOOGLE_SITE_VERIFICATION,
  },
  manifest: '/manifest.json',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="scroll-smooth">
      <body className={`${inter.className} antialiased`}>
        <QueryProvider>
          <ToastProvider>
            <div className="min-h-screen flex flex-col bg-gray-50">
              <Header />
              
              <main className="flex-1">
                {children}
              </main>
              
              <Footer />
            </div>
          </ToastProvider>
        </QueryProvider>
        
        {/* Analytics */}
        {process.env.NODE_ENV === 'production' && (
          <script
            dangerouslySetInnerHTML={{
              __html: `
                window.dataLayer = window.dataLayer || [];
                function gtag(){dataLayer.push(arguments);}
                gtag('js', new Date());
                gtag('config', '${process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID}');
              `,
            }}
          />
        )}
      </body>
    </html>
  );
}