'use client'
import { useSession, signOut } from 'next-auth/react'
import Link from 'next/link'
import Image from 'next/image'
import { useState } from 'react'

export default function Navbar({ currentPage = '' }) {
  const { data: session } = useSession()
  const [menuOpen, setMenuOpen] = useState(false)

  const rol = session?.user?.rol
  const whitelist = session?.user?.whitelist

  return (
    <header>
      <nav className="navbar">
        <div className="nav-container">

          {/* LOGO + ICONOS */}
          <div className="logo-area">
            <Link href="/" className="logo">
              <img src="/logo-olisport.PNG" alt="OliSport Logo" width={100} />
            </Link>

            <div className="auth-icons" style={{ display: 'flex', gap: '8px' }}>
              {session ? (
                <>
                  <Link href="/perfil" className="icon-btn" title="Mi Perfil">
                    <i className="fas fa-user-circle" />
                  </Link>
                  <button
                    onClick={() => signOut({ callbackUrl: '/' })}
                    className="icon-btn"
                    title="Cerrar sesión"
                    style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
                  >
                    <i className="fas fa-sign-out-alt" />
                  </button>
                </>
              ) : (
                <>
                  <Link href="/login" className="icon-btn" title="Iniciar sesión">
                    <i className="fas fa-user" />
                  </Link>
                  <Link href="/register" className="icon-btn" title="Registrarse">
                    <i className="fas fa-user-plus" />
                  </Link>
                </>
              )}
            </div>
          </div>

          {/* MENÚ PRINCIPAL */}
          <ul className="nav-links">
            <li>
              <Link href="/" className={currentPage === 'index' ? 'current' : ''}>Inicio</Link>
            </li>
            <li>
              <Link href="/about" className={currentPage === 'about' ? 'current' : ''}>Quiénes somos</Link>
            </li>
            <li>
              <Link href="/servicio" className={currentPage === 'servicio' ? 'current' : ''}>Servicios</Link>
            </li>
            <li>
              <Link href="/contact" className={currentPage === 'contact' ? 'current' : ''}>Contacto</Link>
            </li>

            {session && (
              <li>
                <Link href="/market" className={currentPage === 'market' ? 'current' : ''}>Market</Link>
              </li>
            )}

            {session && (
              <li>
                <Link href="/perfil" className={currentPage === 'perfil' ? 'current' : ''}>Mi Perfil</Link>
              </li>
            )}

            {/* Panel Trabajador */}
            {session && (rol === 'trabajador' || rol === 'admin') && (
              <li>
                <Link
                  href="/trabajador"
                  className={currentPage === 'trabajador' ? 'current' : ''}
                  title="Panel Trabajador"
                >
                  <i className="fas fa-tools" />
                </Link>
              </li>
            )}

            {/* Panel Admin */}
            {session && rol === 'admin' && (
              <li>
                <Link
                  href="/admin"
                  className={currentPage === 'admin' ? 'current' : ''}
                  title="Panel Administrador"
                >
                  <i className="fas fa-crown" />
                </Link>
              </li>
            )}
          </ul>

          {/* HAMBURGUESA */}
          <div
            className="hamburger"
            onClick={() => setMenuOpen(!menuOpen)}
          >
            ☰
          </div>
        </div>

        {/* MENÚ RESPONSIVE */}
        {menuOpen && (
          <div className="hamburger-menu" style={{ display: 'flex' }}>
            <Link href="/about" onClick={() => setMenuOpen(false)}>Quiénes somos</Link>
            <Link href="/servicio" onClick={() => setMenuOpen(false)}>Servicios</Link>
            <Link href="/contact" onClick={() => setMenuOpen(false)}>Contáctanos</Link>
            {session && (
              <Link href="/market" onClick={() => setMenuOpen(false)}>Market</Link>
            )}
          </div>
        )}

        <hr />
      </nav>
    </header>
  )
}
