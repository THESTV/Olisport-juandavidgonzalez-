import Navbar from '@/components/Navbar'
import Footer from '@/components/Footer'
import Link from 'next/link'

export const metadata = {
  title: 'OliSport | Tienda de Calzado Online',
  description: 'Descubre la última moda en zapatillas para dama, hombre y niños.',
}

export default function HomePage() {
  return (
    <>
      <Navbar currentPage="index" />

      <main style={{ flex: 1 }}>
        {/* ===== BANNER ===== */}
        <section className="banner-header-p1-index">
          <div className="banner-header">
            <div className="banner-header-text">
              <h1 className="banner-title-index">
                Oli<span>Sport</span>
              </h1>
              <div className="text-description-index">
                <hr />
                <p>
                  Descubre la última moda en zapatillas para dama, hombre y niños.
                  En OliSport encontrarás la mejor calidad y atención personalizada.
                  ¡Visítanos y encuentra tu estilo perfecto!
                </p>
              </div>
              <Link href="/contact" className="btn">
                <i className="fa fa-mobile" style={{ marginRight: 5, color: 'black' }} />
                CONTÁCTANOS
              </Link>
            </div>
          </div>
        </section>

        {/* ===== CATÁLOGO ===== */}
        <section className="section Catalogo" id="catalogo">
          <div className="container-catalogo">
            <h3 className="title">CATÁLOGO</h3>
          </div>
        </section>

        <section>
          <div className="card-projects">
            <article className="card">
              <a
                href="https://drive.google.com/drive/folders/1KRzGgS35T0kqeLYk1wT65xI5DcP2ZlF2?usp=sharing"
                target="_blank"
                rel="noopener noreferrer"
              >
                <img
                  src="/portfolio/caballero.jpg"
                  alt="Caballero"
                  className="card-top-img"
                />
                <h3 style={{ color: 'white' }}>Caballero</h3>
              </a>
            </article>

            <article className="card">
              <a
                href="https://drive.google.com/drive/folders/14o_058AfwWfbHlgB8TVJVU4FB2rRyqWJ?usp=drive_link"
                target="_blank"
                rel="noopener noreferrer"
              >
                <img
                  src="/portfolio/dama.jpg"
                  alt="Dama"
                  className="card-top-img"
                />
                <h3 style={{ color: 'white' }}>Dama</h3>
              </a>
            </article>

            <article className="card">
              <a
                href="https://drive.google.com/drive/folders/1hFqvC0nxc_lu4IFNgjlPKSDA1hxnPrC6?usp=sharing"
                target="_blank"
                rel="noopener noreferrer"
              >
                <img
                  src="/portfolio/nino.jpg"
                  alt="Niño"
                  className="card-top-img"
                />
                <h3 style={{ color: 'white' }}>Niño</h3>
              </a>
            </article>
          </div>
        </section>

        {/* ===== CONOCE MÁS ===== */}
        <section className="about-section-home">
          <h2>CONOCE MÁS SOBRE NOSOTROS</h2>
          <div className="section-divider" style={{ margin: '0 auto 32px' }}></div>
          <Link href="/about">
            <button className="btn">
              <i className="fas fa-users" style={{ marginRight: 8 }} />
              Quiénes somos
            </button>
          </Link>
        </section>
      </main>

      <Footer />
    </>
  )
}
