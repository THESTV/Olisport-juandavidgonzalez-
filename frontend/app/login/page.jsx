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
  const [loadingGoogle, setLoadingGoogle] = useState(false)

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

  const handleGoogle = async () => {
    setLoadingGoogle(true)
    await signIn('google', { callbackUrl: '/market' })
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

              <button type="submit" className="login-btn" disabled={loading}>
                {loading ? 'Ingresando...' : 'Ingresar'}
              </button>

              {/* DIVISOR */}
              <div style={{
                display: 'flex', alignItems: 'center', gap: 12, margin: '8px 0'
              }}>
                <hr style={{ flex: 1, borderColor: 'rgba(255,255,255,0.15)' }} />
                <span style={{ color: 'rgba(255,255,255,0.4)', fontSize: '0.85rem' }}>o</span>
                <hr style={{ flex: 1, borderColor: 'rgba(255,255,255,0.15)' }} />
              </div>

              {/* BOTÓN GOOGLE */}
              <button
                type="button"
                onClick={handleGoogle}
                disabled={loadingGoogle}
                style={{
                  width: '100%',
                  padding: '12px 20px',
                  background: 'white',
                  color: '#333',
                  border: '1px solid #ddd',
                  borderRadius: 4,
                  fontWeight: 700,
                  fontSize: '0.95rem',
                  fontFamily: 'Raleway, sans-serif',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 10,
                  transition: 'box-shadow 0.2s',
                  opacity: loadingGoogle ? 0.7 : 1,
                }}
              >
                <img
                  src="https://www.google.com/favicon.ico"
                  alt="Google"
                  style={{ width: 18, height: 18 }}
                />
                {loadingGoogle ? 'Redirigiendo...' : 'Continuar con Google'}
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
