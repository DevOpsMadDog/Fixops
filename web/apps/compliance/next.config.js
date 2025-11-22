/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: '/compliance',
  assetPrefix: '/compliance',
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
}

module.exports = nextConfig
