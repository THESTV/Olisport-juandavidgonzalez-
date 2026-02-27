import Navbar from '@/components/Navbar'
import Footer from '@/components/Footer'

export const metadata = { title: 'Servicios | OliSport' }

export default function ServicioPage() {
  const servicios = [
    { icono: 'fas fa-truck', titulo: 'Envío a Domicilio', desc: 'Recibe tus zapatillas directamente en la puerta de tu casa con envíos rápidos y seguros.' },
    { icono: 'fas fa-star', titulo: 'Marcas Premium', desc: 'Trabajamos con las mejores marcas internacionales para garantizar calidad y autenticidad.' },
    { icono: 'fas fa-exchange-alt', titulo: 'Cambios y Devoluciones', desc: 'Si el producto no es lo que esperabas, te ayudamos con cambios o devoluciones sin complicaciones.' },
    { icono: 'fas fa-headset', titulo: 'Atención Personalizada', desc: 'Nuestro equipo está disponible para asesorarte en la elección del calzado perfecto.' },
    { icono: 'fas fa-tags', titulo: 'Precios Competitivos', desc: 'Ofrecemos los mejores precios del mercado sin sacrificar la calidad de los productos.' },
    { icono: 'fas fa-shield-alt', titulo: 'Compra Segura', desc: 'Todos nuestros productos son 100% originales y cuentan con garantía del fabricante.' },
  ]

  return (
    <>
      <Navbar currentPage="servicio" />
      <main style={{ flex: 1 }}>
        <section className="banner-header-p1-index">
          <div className="banner-header">
            <h1 className="banner-title-admin">Nuestros <span>Servicios</span></h1>
          </div>
        </section>

        <section style={{ maxWidth: 1000, margin: '0 auto', padding: '40px 24px' }}>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
            gap: 24,
          }}>
            {servicios.map((s, i) => (
              <div key={i} style={{
                background: 'rgba(255,255,255,0.05)',
                border: '1px solid rgba(0,229,255,0.2)',
                borderRadius: 12,
                padding: '28px 24px',
                transition: 'transform 0.3s, box-shadow 0.3s',
              }}>
                <div style={{ color: 'rgb(0,229,255)', fontSize: '2rem', marginBottom: 12 }}>
                  <i className={s.icono} />
                </div>
                <h3 style={{ fontSize: '1.1rem', marginBottom: 10 }}>{s.titulo}</h3>
                <p style={{ color: 'rgba(255,255,255,0.65)', lineHeight: 1.7, margin: 0 }}>{s.desc}</p>
              </div>
            ))}
          </div>
        </section>
      </main>
      <Footer subtitle="Servicios OliSport" />
    </>
  )
}
