/** @type {import('next').NextConfig} */
const apiUrl = process.env.NEXT_PUBLIC_API_URL;

if (!apiUrl && process.env.NODE_ENV === "production") {
  throw new Error("NEXT_PUBLIC_API_URL is required for production dashboard builds");
}

const nextConfig = {
  output: "standalone",
  turbopack: {
    root: __dirname,
  },
  env: {
    NEXT_PUBLIC_API_URL: apiUrl || "",
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
