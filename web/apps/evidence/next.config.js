/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: '/evidence',
  assetPrefix: '/evidence',
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
}

module.exports = nextConfig
