/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: '/dashboard',
  assetPrefix: '/dashboard',
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
}

module.exports = nextConfig
