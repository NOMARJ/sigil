import { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Analytics | Sigil Pro',
  description: 'Usage analytics and insights for your security analysis activities',
};

export default function AnalyticsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}