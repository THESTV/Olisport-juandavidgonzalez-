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

          <div style={{ marginTop: 32, display: 'flex', gap: 24, flexWrap: 'wrap' }}>
            <div style={{
              background: 'rgba(0,229,255,0.08)', border: '1px solid rgba(0,229,255,0.25)',
              borderRadius: 12, padding: '24px 28px', flex: '1 1 200px'
            }}>
              <h3 style={{ color: 'rgb(0,229,255)', marginBottom: 8, fontSize: '2rem' }}>+5</h3>
              <p style={{ margin: 0 }}>Años de experiencia en el mercado</p>
            </div>
            <div style={{
              background: 'rgba(0,229,255,0.08)', border: '1px solid rgba(0,229,255,0.25)',
              borderRadius: 12, padding: '24px 28px', flex: '1 1 200px'
            }}>
              <h3 style={{ color: 'rgb(0,229,255)', marginBottom: 8, fontSize: '2rem' }}>+100</h3>
              <p style={{ margin: 0 }}>Modelos disponibles</p>
            </div>
            <div style={{
              background: 'rgba(0,229,255,0.08)', border: '1px solid rgba(0,229,255,0.25)',
              borderRadius: 12, padding: '24px 28px', flex: '1 1 200px'
            }}>
              <h3 style={{ color: 'rgb(0,229,255)', marginBottom: 8, fontSize: '2rem' }}>3</h3>
              <p style={{ margin: 0 }}>Categorías: Dama, Caballero y Niño</p>
            </div>
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
