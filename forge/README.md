# Sigil Forge Frontend

The official frontend for Sigil Forge - an AI Agent Tool Discovery Platform that helps developers find, evaluate, and deploy AI agent tools with confidence.

## Features

🔍 **Smart Discovery** - Search through thousands of AI agent tools, MCP servers, and Claude skills
🛡️ **Trust Scores** - Comprehensive security scanning and trust evaluation for every tool
📊 **Detailed Analytics** - Track usage, popularity, and community feedback
🎯 **Stack Recommendations** - Get personalized tool stack suggestions for your use case
🔧 **Publisher Tools** - Badge generation and integration guides for tool publishers
📱 **Responsive Design** - Mobile-first design that works on all devices

## Tech Stack

- **Framework**: Next.js 14 with App Router
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **State Management**: Zustand + React Query
- **UI Components**: Headless UI + Custom Design System
- **Icons**: Heroicons
- **Analytics**: Vercel Analytics

## Getting Started

### Prerequisites

- Node.js 18.0.0 or later
- npm or yarn package manager

### Installation

1. Install dependencies:
```bash
npm install
```

2. Copy environment variables:
```bash
cp .env.example .env.local
```

3. Configure environment variables in `.env.local`:
```env
NEXT_PUBLIC_FORGE_API_URL=http://localhost:8000
NEXT_PUBLIC_FORGE_WS_URL=ws://localhost:8000
```

### Development

Start the development server:
```bash
npm run dev
```

The application will be available at [http://localhost:3001](http://localhost:3001).

### Building for Production

```bash
npm run build
npm start
```

## Project Structure

```
src/
├── app/                    # Next.js App Router pages
│   ├── discover/          # Tool discovery and search
│   ├── tools/[id]/        # Individual tool pages  
│   ├── stacks/            # Tool stack pages
│   ├── categories/        # Category browsing
│   └── layout.tsx         # Root layout
├── components/            # React components
│   ├── ui/               # Design system components
│   ├── layout/           # Layout components
│   ├── home/             # Homepage sections
│   ├── discover/         # Search interface
│   └── tools/            # Tool-specific components
├── lib/                   # Utilities and API client
│   ├── api.ts            # Forge API client
│   └── utils.ts          # Helper functions
├── hooks/                 # Custom React hooks
├── types/                 # TypeScript definitions
└── store/                # State management
```

## Key Components

### Design System

The application includes a comprehensive design system with:

- **Buttons** - Multiple variants (primary, secondary, outline, ghost, danger)
- **Badges** - Trust score indicators and ecosystem labels
- **Cards** - Tool cards, stack cards with hover effects
- **Search** - Advanced search input with autocomplete
- **Loading** - Skeleton loaders and spinners
- **Modals** - Overlays and side drawers

### Search & Discovery

- **Advanced Filtering** - Filter by ecosystem, category, trust score, tags
- **Real-time Search** - Debounced search with autocomplete suggestions
- **Sort Options** - Relevance, trust score, popularity, date
- **Saved Searches** - Bookmark and reuse common searches
- **URL State** - Search state persisted in URL for sharing

### Trust Score Visualization

- **Color-coded Scores** - Visual indicators for trust levels
- **Breakdown Charts** - Detailed factor analysis
- **Progress Bars** - Weighted scoring visualization
- **Trend Indicators** - Score changes over time

## API Integration

The frontend connects to the Sigil Forge API for:

- **Tool Search** - Full-text search with filters
- **Tool Details** - Complete tool information and metadata
- **Trust Scores** - Security analysis and community metrics
- **Stack Recommendations** - AI-powered tool suggestions
- **Analytics** - Usage tracking and insights

### API Client

```typescript
import { forgeApi } from '@/lib/api';

// Search tools
const results = await forgeApi.searchTools('web scraping', {
  categories: ['automation'],
  trust_score_min: 70
});

// Get tool details
const tool = await forgeApi.getTool('tool-id');

// Generate stack recommendation
const recommendation = await forgeApi.generateStack(
  'I need tools for data analysis',
  ['python', 'visualization', 'ML']
);
```

## Performance Optimizations

- **Code Splitting** - Automatic route-based splitting
- **Image Optimization** - Next.js Image component
- **API Caching** - React Query with smart invalidation
- **Bundle Analysis** - Optimized imports and tree shaking
- **SEO Ready** - Server-side rendering with metadata

## Accessibility

The application follows WCAG 2.1 guidelines:

- **Semantic HTML** - Proper heading structure and landmarks
- **Keyboard Navigation** - Full keyboard accessibility
- **Screen Readers** - ARIA labels and descriptions
- **Color Contrast** - Meets AA contrast requirements
- **Focus Management** - Visible focus indicators

## Browser Support

- Chrome (last 2 versions)
- Firefox (last 2 versions)
- Safari (last 2 versions)
- Edge (last 2 versions)

## Contributing

This is part of the larger Sigil project. See the main repository for contribution guidelines.

## License

Licensed under the same terms as the Sigil project.

## Support

- **Documentation**: [forge.sigilsec.ai/docs](https://forge.sigilsec.ai/docs)
- **Issues**: GitHub Issues in the main Sigil repository
- **Discord**: [Sigil Community](https://discord.gg/sigil)