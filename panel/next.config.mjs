/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: "standalone",
  eslint: {
    // Only lint the application source tree; avoids Next.js mis-resolving
    // the npm script name "lint" as a directory when using flat ESLint config.
    dirs: ["src"],
  },
};

export default nextConfig;
