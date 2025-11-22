/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: '/automations',
  assetPrefix: '/automations',
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
}

module.exports = nextConfig
