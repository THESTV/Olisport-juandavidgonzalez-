'use client'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'
import Navbar from '@/components/Navbar'
import Footer from '@/components/Footer'

// Productos de ejemplo — se reemplazarán por datos reales del backend
const PRODUCTOS_EJEMPLO = [
  {
    id: 1, nombre: 'Nike Air Max', categoria: 'Caballero',
    precio: 320000, talla: '42', imagen: '/portfolio/caballero.jpg'
  },
  {
    id: 2, nombre: 'Adidas Ultraboost', categoria: 'Dama',
    precio: 290000, talla: '37', imagen: '/portfolio/dama.jpg'
  },
  {
    id: 3, nombre: 'Puma RS-X', categoria: 'Niño',
    precio: 180000, talla: '32', imagen: '/portfolio/nino.jpg'
  },
  {
    id: 4, nombre: 'New Balance 574', categoria: 'Caballero',
    precio: 260000, talla: '43', imagen: '/portfolio/caballero.jpg'
  },
  {
    id: 5, nombre: 'Skechers D\'Lites', categoria: 'Dama',
    precio: 210000, talla: '38', imagen: '/portfolio/dama.jpg'
  },
  {
    id: 6, nombre: 'Nike Revolution', categoria: 'Niño',
    precio: 150000, talla: '30', imagen: '/portfolio/nino.jpg'
  },
]

export default function MarketPage() {
  const { data: session, status } = useSession()
  const router = useRouter()
  const [productos, setProductos] = useState(PRODUCTOS_EJEMPLO)
  const [filtroCategoria, setFiltroCategoria] = useState('Todos')
  const [busqueda, setBusqueda] = useState('')

  useEffect(() => {
    if (status === 'unauthenticated') router.push('/login')
  }, [status, router])

  // Intenta cargar productos reales del backend
  useEffect(() => {
    const cargarProductos = async () => {
      try {
        const res = await fetch('/flask/api/productos')
        if (res.ok) {
          const data = await res.json()
          if (data.productos && data.productos.length > 0) {
            setProductos(data.productos)
          }
        }
      } catch {
        // Si falla, usa los productos de ejemplo
        console.log('Usando productos de ejemplo')
      }
    }
    if (status === 'authenticated') cargarProductos()
  }, [status])

  const productosFiltrados = productos.filter((p) => {
    const coincideCategoria = filtroCategoria === 'Todos' || p.categoria === filtroCategoria
    const coincideBusqueda =
      p.nombre.toLowerCase().includes(busqueda.toLowerCase()) ||
      p.categoria.toLowerCase().includes(busqueda.toLowerCase())
    return coincideCategoria && coincideBusqueda
  })

  const formatPrecio = (p) =>
    new Intl.NumberFormat('es-CO', { style: 'currency', currency: 'COP', minimumFractionDigits: 0 }).format(p)

  if (status === 'loading') {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
        <p>Cargando...</p>
      </div>
    )
  }

  return (
    <>
      <Navbar currentPage="market" />

      <main style={{ flex: 1 }}>
        {/* BANNER */}
        <section className="banner-header-p1-index">
          <div className="banner-header">
            <div className="banner-header-text">
              <h1 className="banner-title-index">
                Oli<span>Market</span>
              </h1>
              <div className="text-description-index">
                <hr />
                <p>Explora nuestra colección completa de calzado.</p>
              </div>
            </div>
          </div>
        </section>

        {/* FILTROS */}
        <section style={{ padding: '24px 20px', maxWidth: 1100, margin: '0 auto' }}>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
            {/* Búsqueda */}
            <input
              type="text"
              placeholder="🔍 Buscar producto..."
              value={busqueda}
              onChange={(e) => setBusqueda(e.target.value)}
              style={{
                flex: 1, minWidth: 200,
                background: 'rgba(255,255,255,0.08)',
                border: '1px solid rgba(0,229,255,0.3)',
                borderRadius: 8, padding: '10px 14px',
                color: 'white', fontSize: '1rem',
                fontFamily: 'Raleway, sans-serif', outline: 'none',
              }}
            />

            {/* Filtro categoría */}
            {['Todos', 'Caballero', 'Dama', 'Niño'].map((cat) => (
              <button
                key={cat}
                onClick={() => setFiltroCategoria(cat)}
                style={{
                  padding: '9px 18px',
                  borderRadius: 8,
                  border: filtroCategoria === cat
                    ? '2px solid rgb(0,229,255)'
                    : '1px solid rgba(255,255,255,0.2)',
                  background: filtroCategoria === cat ? 'rgba(0,229,255,0.15)' : 'transparent',
                  color: filtroCategoria === cat ? 'rgb(0,229,255)' : 'white',
                  cursor: 'pointer',
                  fontWeight: 600,
                  fontFamily: 'Raleway, sans-serif',
                  transition: '0.2s',
                }}
              >
                {cat}
              </button>
            ))}
          </div>
        </section>

        {/* PRODUCTOS */}
        <section>
          {productosFiltrados.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 60, color: 'rgba(255,255,255,0.5)' }}>
              <i className="fas fa-search" style={{ fontSize: 40, marginBottom: 16, display: 'block' }} />
              <p>No se encontraron productos para &quot;{busqueda}&quot;</p>
            </div>
          ) : (
            <div className="market-grid">
              {productosFiltrados.map((p) => (
                <div key={p.id} className="product-card">
                  <img src={p.imagen || '/portfolio/caballero.jpg'} alt={p.nombre} />
                  <div className="product-card-body">
                    <h4>{p.nombre}</h4>
                    <p>{p.categoria} · Talla {p.talla}</p>
                    <p className="product-price">{formatPrecio(p.precio)}</p>
                    <button className="btn" style={{ marginTop: 12, width: '100%', fontSize: '0.9rem' }}>
                      <i className="fas fa-shopping-cart" style={{ marginRight: 6 }} />
                      Ver producto
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* CATÁLOGOS EXTERNOS */}
        <section className="section">
          <div className="container-catalogo">
            <h3 className="title">CATÁLOGOS COMPLETOS</h3>
          </div>
        </section>
        <section>
          <div className="card-projects" style={{ paddingBottom: 40 }}>
            <article className="card">
              <a href="https://drive.google.com/drive/folders/1KRzGgS35T0kqeLYk1wT65xI5DcP2ZlF2?usp=sharing" target="_blank" rel="noopener noreferrer">
                <img className="card-top-img" src="/portfolio/caballero.jpg" alt="Caballero" />
                <h3 style={{ color: 'white' }}>Caballero</h3>
              </a>
            </article>
            <article className="card">
              <a href="https://drive.google.com/drive/folders/14o_058AfwWfbHlgB8TVJVU4FB2rRyqWJ?usp=drive_link" target="_blank" rel="noopener noreferrer">
                <img className="card-top-img" src="/portfolio/dama.jpg" alt="Dama" />
                <h3 style={{ color: 'white' }}>Dama</h3>
              </a>
            </article>
            <article className="card">
              <a href="https://drive.google.com/drive/folders/1hFqvC0nxc_lu4IFNgjlPKSDA1hxnPrC6?usp=sharing" target="_blank" rel="noopener noreferrer">
                <img className="card-top-img" src="/portfolio/nino.jpg" alt="Niño" />
                <h3 style={{ color: 'white' }}>Niño</h3>
              </a>
            </article>
          </div>
        </section>
      </main>

      <Footer />
    </>
  )
}
