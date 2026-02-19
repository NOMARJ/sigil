/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000",
    NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL || "",
    NEXT_PUBLIC_SUPABASE_ANON_KEY: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || "",
  },
  async redirects() {
    return [
      {
        source: "/install.sh",
        destination:
          "https://raw.githubusercontent.com/NOMARJ/sigil/main/install.sh",
        permanent: true,
      },
    ];
  },
};

module.exports = nextConfig;
