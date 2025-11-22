/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: '/risk',
  assetPrefix: '/risk',
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
}

module.exports = nextConfig
