'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import Navbar from '@/components/Navbar'
import Footer from '@/components/Footer'

export default function RegisterPage() {
  const router = useRouter()
  const [form, setForm] = useState({ nombre: '', correo: '', password: '', password2: '' })
  const [mensaje, setMensaje] = useState({ tipo: '', texto: '' })
  const [loading, setLoading] = useState(false)

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setMensaje({ tipo: '', texto: '' })

    if (form.password !== form.password2) {
      setMensaje({ tipo: 'error', texto: 'Las contraseñas no coinciden' })
      return
    }

    setLoading(true)
    try {
      const res = await fetch('/flask/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          nombre: form.nombre,
          correo: form.correo,
          password: form.password,
        }),
      })
      const data = await res.json()

      if (res.ok && data.success) {
        setMensaje({ tipo: 'success', texto: '¡Cuenta creada! Redirigiendo...' })
        setTimeout(() => router.push('/login'), 1800)
      } else {
        setMensaje({ tipo: 'error', texto: data.error || 'Error al registrar' })
      }
    } catch {
      setMensaje({ tipo: 'error', texto: 'Error de conexión con el servidor' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <Navbar currentPage="register" />

      <main style={{ flex: 1 }}>
        <section className="auth-section">
          <div className="register-box">

            <div className="register-logo">
              <img src="/logo-olisport.PNG" alt="OliSport Logo" />
            </div>

            <h2 className="register-title">Crear Cuenta</h2>
            <p className="register-subtitle">Únete a OliSport y comienza ahora</p>

            {mensaje.texto && (
              <div className="flash-container">
                <div className={`flash-message ${mensaje.tipo}`}>{mensaje.texto}</div>
              </div>
            )}

            <form onSubmit={handleSubmit} className="form-container">
              <div className="form-group">
                <label>Nombre completo</label>
                <input
                  type="text"
                  name="nombre"
                  placeholder="Tu nombre"
                  value={form.nombre}
                  onChange={handleChange}
                  required
                />
              </div>
              <div className="form-group">
                <label>Correo electrónico</label>
                <input
                  type="email"
                  name="correo"
                  placeholder="correo@ejemplo.com"
                  value={form.correo}
                  onChange={handleChange}
                  required
                />
              </div>
              <div className="form-group">
                <label>Contraseña</label>
                <input
                  type="password"
                  name="password"
                  placeholder="Mínimo 6 caracteres"
                  value={form.password}
                  onChange={handleChange}
                  required
                />
              </div>
              <div className="form-group">
                <label>Confirmar contraseña</label>
                <input
                  type="password"
                  name="password2"
                  placeholder="Repite tu contraseña"
                  value={form.password2}
                  onChange={handleChange}
                  required
                />
              </div>

              <button type="submit" className="register-btn" disabled={loading}>
                {loading ? 'Creando cuenta...' : 'Crear cuenta'}
              </button>
            </form>

            <p className="form-footer">
              ¿Ya tienes cuenta?{' '}
              <Link href="/login">Inicia sesión</Link>
            </p>
          </div>
        </section>
      </main>

      <Footer />
    </>
  )
}
