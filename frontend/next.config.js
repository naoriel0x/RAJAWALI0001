/** @type {import("next").NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: "standalone",
  async rewrites() {
    const defaultApiUrl =
      process.env.NODE_ENV === "development"
        ? "http://127.0.0.1:8000"
        : "http://backend:8000";
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || defaultApiUrl;
    return [
      {
        source: "/api/:path*",
        destination: `${apiUrl}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
