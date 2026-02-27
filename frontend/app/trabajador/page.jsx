'use client'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { useEffect } from 'react'
import Navbar from '@/components/Navbar'
import Footer from '@/components/Footer'

export default function TrabajadorPage() {
  const { data: session, status } = useSession()
  const router = useRouter()

  useEffect(() => {
    if (status === 'unauthenticated') {
      router.push('/login')
      return
    }
    if (status === 'authenticated') {
      const rol = session?.user?.rol
      const whitelist = session?.user?.whitelist
      // Trabajador sin whitelist → redirige al market
      if (rol === 'trabajador' && !whitelist) {
        router.push('/market')
      }
      // Usuario normal → redirige al market
      if (rol === 'usuario') {
        router.push('/market')
      }
    }
  }, [status, session, router])

  if (status === 'loading') {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
        <p>Cargando...</p>
      </div>
    )
  }

  return (
    <>
      <Navbar currentPage="trabajador" />

      <main style={{ flex: 1 }}>
        {/* BANNER */}
        <section className="banner-header-p1-index">
          <div className="banner-header">
            <div className="banner-header-text">
              <h1 className="banner-title-admin">
                Panel de <span>Trabajo</span>
              </h1>
              <div className="text-description-index">
                <hr />
                <p>
                  Bienvenido <strong>{session?.user?.name}</strong>.
                  Este es tu panel de trabajo en OliSport. Aquí puedes gestionar
                  inventario, ver pedidos, revisar reportes y más.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* HERRAMIENTAS */}
        <section className="section">
          <div className="container-catalogo">
            <h3 className="title">HERRAMIENTAS DE TRABAJO</h3>
          </div>
        </section>

        <section>
          <div className="card-projects">
            {/* INVENTARIO */}
            <article className="card">
              <a href="#" onClick={(e) => e.preventDefault()}>
                <img
                  className="card-top-img"
                  src="/portfolio/inventario.jpg"
                  alt="Inventario"
                />
                <h3 style={{ color: 'white' }}>Inventario</h3>
              </a>
            </article>

            {/* PEDIDOS */}
            <article className="card">
              <a href="#" onClick={(e) => e.preventDefault()}>
                <img
                  className="card-top-img"
                  src="/portfolio/pedido.jpg"
                  alt="Pedidos"
                />
                <h3 style={{ color: 'white' }}>Pedidos</h3>
              </a>
            </article>

            {/* REPORTES */}
            <article className="card">
              <a href="#" onClick={(e) => e.preventDefault()}>
                <img
                  className="card-top-img"
                  src="/portfolio/reportes.jpg"
                  alt="Reportes"
                />
                <h3 style={{ color: 'white' }}>Reportes</h3>
              </a>
            </article>
          </div>
        </section>
      </main>

      <Footer subtitle="Panel de Trabajo" />
    </>
  )
}
