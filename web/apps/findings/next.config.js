/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: '/findings',
  assetPrefix: '/findings',
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
}

module.exports = nextConfig
