import './globals.css'
import Providers from '@/components/Providers'

export const metadata = {
  title: 'OliSport | 👟⚡',
  description: 'Tienda de calzado online — Dama, Caballero y Niño',
}

export default function RootLayout({ children }) {
  return (
    <html lang="es">
      <head>
        <link
          href="https://fonts.googleapis.com/css2?family=Raleway:wght@400;600;700&display=swap"
          rel="stylesheet"
        />
        <link
          rel="stylesheet"
          href="https://use.fontawesome.com/releases/v5.6.1/css/all.css"
          crossOrigin="anonymous"
        />
      </head>
<body
  style={{
    display: 'flex',
    flexDirection: 'column',
    minHeight: '100vh',
  }}
>
  <div className="user-site-bg">
    <Providers>
      {children}
    </Providers>
  </div>
</body>
    </html>
  )
}
