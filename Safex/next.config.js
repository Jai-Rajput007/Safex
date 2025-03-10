/** @type {import('next').NextConfig} */
const nextConfig = {
    images: {
      remotePatterns: [
        {
          protocol: "https",
          hostname: "aceternity.com",
          port: "", // Leave empty unless a specific port is required
          pathname: "/images/products/thumbnails/new/**", // Restrict to specific path (optional)
        },
      ],
    },
  };
  
  module.exports = nextConfig;