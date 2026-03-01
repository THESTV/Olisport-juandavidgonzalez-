import Navbar from '@/components/Navbar'
import Footer from '@/components/Footer'
import Link from 'next/link'

export const metadata = { title: 'Quiénes somos | OliSport' }

export default function AboutPage() {
  return (
    <>
      <Navbar currentPage="about" />
      <main style={{ flex: 1 }}>
        <section className="banner-header-p1-index">
          <div className="banner-header">
            <h1 className="banner-title-admin">Quiénes <span>Somos</span></h1>
          </div>
        </section>

        <section className="page-section">
          <h2>Nuestra Historia</h2>
          <p>
            Somos una microempresa especializada en la venta de zapatillas de las mejores marcas
            internacionales, ofreciendo una amplia variedad de modelos y estilos de alta calidad.
          </p>
          <p>
            Nuestra misión es brindarte la mejor experiencia de compra, con productos auténticos
            y un servicio personalizado. Nuestro equipo está aquí para ayudarte a encontrar la
            mejor opción para tu emprendimiento o uso cotidiano, asesorándote en la elección del
            calzado perfecto que se adapte a tus necesidades y estilo.
          </p>

          <div style={{ marginTop: 32, display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
            {[
              { numero: '+5', label: 'Años en el mercado' },
              { numero: '+100', label: 'Modelos disponibles' },
              { numero: '3', label: 'Categorías' },
            ].map((stat, i) => (
              <div key={i} style={{
                background: 'rgba(0,229,255,0.06)',
                border: '1px solid rgba(0,229,255,0.2)',
                borderRadius: 12, padding: '28px 20px', textAlign: 'center'
              }}>
                <div style={{ fontSize: '2rem', fontWeight: 700, color: 'rgb(0,229,255)', marginBottom: 6 }}>
                  {stat.numero}
                </div>
                <div style={{ color: 'rgba(255,255,255,0.55)', fontSize: '0.88rem' }}>{stat.label}</div>
              </div>
            ))}
          </div>

          <div style={{ marginTop: 40 }}>
            <Link href="/contact" className="btn">
              <i className="fa fa-mobile" style={{ marginRight: 8, color: '#030344' }} />
              CONTÁCTANOS
            </Link>
          </div>
        </section>
      </main>
      <Footer />
    </>
  )
}
