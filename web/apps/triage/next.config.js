/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: '/triage',
  assetPrefix: '/triage',
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
}

module.exports = nextConfig
