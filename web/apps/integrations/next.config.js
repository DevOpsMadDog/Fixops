/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: '/integrations',
  assetPrefix: '/integrations',
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
}

module.exports = nextConfig
