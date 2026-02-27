'use client'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { useState, useEffect } from 'react'
import Navbar from '@/components/Navbar'
import Footer from '@/components/Footer'

export default function PerfilPage() {
  const { data: session, status, update } = useSession()
  const router = useRouter()
  const [form, setForm] = useState({ nombre: '', correo: '', direccion: '', password: '' })
  const [mensaje, setMensaje] = useState({ tipo: '', texto: '' })
  const [loading, setLoading] = useState(false)

  // Redirige si no está autenticado
  useEffect(() => {
    if (status === 'unauthenticated') router.push('/login')
  }, [status, router])

  // Precarga los datos del usuario en el formulario
  useEffect(() => {
    if (session?.user) {
      setForm({
        nombre: session.user.name || '',
        correo: session.user.email || '',
        direccion: session.user.direccion || '',
        password: '',
      })
    }
  }, [session])

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value })

  const handleSubmit = async (e) => {
    e.preventDefault()
    setMensaje({ tipo: '', texto: '' })
    setLoading(true)

    try {
      const res = await fetch('/flask/api/perfil', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: session.user.id,
          nombre: form.nombre,
          correo: form.correo,
          direccion: form.direccion,
          password: form.password || null,
        }),
      })
      const data = await res.json()

      if (res.ok && data.success) {
        setMensaje({ tipo: 'success', texto: '¡Perfil actualizado correctamente!' })
        // Actualiza la sesión con los nuevos datos
        await update({ name: form.nombre, email: form.correo })
        setForm((f) => ({ ...f, password: '' }))
      } else {
        setMensaje({ tipo: 'error', texto: data.error || 'Error al actualizar' })
      }
    } catch {
      setMensaje({ tipo: 'error', texto: 'Error de conexión con el servidor' })
    } finally {
      setLoading(false)
    }
  }

  if (status === 'loading') {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
        <p>Cargando...</p>
      </div>
    )
  }

  return (
    <>
      <Navbar currentPage="perfil" />

      <main style={{ flex: 1 }}>
        {mensaje.texto && (
          <div className="flash-container" style={{ maxWidth: 500, margin: '20px auto 0', padding: '0 20px' }}>
            <div className={`flash-message ${mensaje.tipo}`}>{mensaje.texto}</div>
          </div>
        )}

        <section className="perfil-unificado">
          <div className="perfil-card">

            <div className="perfil-header">
              <img src="/logo-olisport.PNG" alt="Avatar" className="perfil-avatar" />
              <h2>{session?.user?.name}</h2>
              <p className="perfil-correo">{session?.user?.email}</p>
              <span
                className={`badge ${session?.user?.rol}`}
                style={{ marginTop: 8 }}
              >
                {session?.user?.rol}
              </span>
            </div>

            <hr className="divider" />

            <form onSubmit={handleSubmit} className="perfil-form">
              <h3 style={{ marginBottom: 8 }}>Información Personal</h3>

              <label>Nombre completo</label>
              <input
                type="text"
                name="nombre"
                value={form.nombre}
                onChange={handleChange}
                required
              />

              <label>Correo electrónico</label>
              <input
                type="email"
                name="correo"
                value={form.correo}
                onChange={handleChange}
                required
              />

              <label>Dirección</label>
              <input
                type="text"
                name="direccion"
                value={form.direccion}
                onChange={handleChange}
                placeholder="Tu dirección de envío"
              />

              <label>Nueva contraseña (opcional)</label>
              <input
                type="password"
                name="password"
                value={form.password}
                onChange={handleChange}
                placeholder="••••••••"
              />

              <button type="submit" className="btn-primary guardar-btn" disabled={loading}>
                {loading ? 'Guardando...' : 'Guardar Cambios'}
              </button>
            </form>
          </div>
        </section>
      </main>

      <Footer />
    </>
  )
}
