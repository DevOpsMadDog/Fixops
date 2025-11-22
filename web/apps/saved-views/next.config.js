/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: '/saved-views',
  assetPrefix: '/saved-views',
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
}

module.exports = nextConfig
