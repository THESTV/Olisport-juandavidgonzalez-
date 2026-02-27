'use client'
import { useState } from 'react'
import { signIn } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import Navbar from '@/components/Navbar'
import Footer from '@/components/Footer'

export default function LoginPage() {
  const router = useRouter()
  const [correo, setCorreo] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    const result = await signIn('credentials', {
      correo,
      password,
      redirect: false,
    })

    setLoading(false)

    if (result?.error) {
      setError(result.error)
      return
    }

    // Redirige según el rol — obtenemos la sesión actualizada
    const res = await fetch('/api/auth/session')
    const session = await res.json()
    const rol = session?.user?.rol

    if (rol === 'admin') {
      router.push('/admin')
    } else if (rol === 'trabajador') {
      router.push('/trabajador')
    } else {
      router.push('/market')
    }
  }

  return (
    <>
      <Navbar currentPage="login" />

      <main style={{ flex: 1 }}>
        <section className="auth-section login-section">
          <div className="login-box">

            <div className="login-logo">
              <img src="/logo-olisport.PNG" alt="OliSport Logo" />
            </div>

            <h2 className="login-title">Bienvenido de nuevo</h2>
            <p className="login-subtitle">Inicia sesión para continuar</p>

            {/* MENSAJES DE ERROR */}
            {error && (
              <div className="flash-container">
                <div className="flash-message error">{error}</div>
              </div>
            )}

            <form onSubmit={handleSubmit} className="form-container">
              <div className="form-group">
                <label>Correo electrónico</label>
                <input
                  type="email"
                  placeholder="correo@ejemplo.com"
                  value={correo}
                  onChange={(e) => setCorreo(e.target.value)}
                  required
                  autoComplete="email"
                />
              </div>

              <div className="form-group">
                <label>Contraseña</label>
                <input
                  type="password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoComplete="current-password"
                />
              </div>

              <button
                type="submit"
                className="login-btn"
                disabled={loading}
              >
                {loading ? 'Ingresando...' : 'Ingresar'}
              </button>
            </form>

            <p className="form-footer">
              ¿No tienes cuenta?{' '}
              <Link href="/register">Regístrate</Link>
            </p>
          </div>
        </section>
      </main>

      <Footer />
    </>
  )
}
