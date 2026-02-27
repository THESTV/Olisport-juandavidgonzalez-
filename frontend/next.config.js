/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        // Todas las llamadas a /flask/* se redirigen al backend Flask
        source: '/flask/:path*',
        destination: 'http://localhost:5000/:path*',
      },
    ]
  },
}

module.exports = nextConfig
