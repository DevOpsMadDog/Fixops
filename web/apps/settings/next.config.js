/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: '/settings',
  assetPrefix: '/settings',
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
}

module.exports = nextConfig
