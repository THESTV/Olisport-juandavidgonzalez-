'use client'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { useState, useEffect } from 'react'
import Navbar from '@/components/Navbar'
import Footer from '@/components/Footer'

export default function AdminPage() {
  const { data: session, status } = useSession()
  const router = useRouter()

  const [usuarios, setUsuarios] = useState([])
  const [loadingData, setLoadingData] = useState(true)
  const [mensaje, setMensaje] = useState({ tipo: '', texto: '' })

  // Modal crear usuario
  const [modalCrear, setModalCrear] = useState(false)
  const [formCrear, setFormCrear] = useState({ nombre: '', correo: '', direccion: '', password: '', rol: 'usuario' })

  // Modal editar usuario
  const [modalEditar, setModalEditar] = useState(false)
  const [formEditar, setFormEditar] = useState({ id: '', nombre: '', correo: '', direccion: '', password: '', rol: '' })

  // ---- Protección de ruta ----
  useEffect(() => {
    if (status === 'unauthenticated') router.push('/login')
    if (status === 'authenticated' && session?.user?.rol !== 'admin') router.push('/market')
  }, [status, session, router])

  // ---- Cargar usuarios ----
  const cargarUsuarios = async () => {
    setLoadingData(true)
    try {
      const res = await fetch('/flask/api/usuarios')
      const data = await res.json()
      setUsuarios(data.usuarios || [])
    } catch {
      setMensaje({ tipo: 'error', texto: 'Error al cargar usuarios' })
    } finally {
      setLoadingData(false)
    }
  }

  useEffect(() => {
    if (status === 'authenticated' && session?.user?.rol === 'admin') {
      cargarUsuarios()
    }
  }, [status, session])

  // ---- Mostrar mensaje temporal ----
  const mostrarMensaje = (tipo, texto) => {
    setMensaje({ tipo, texto })
    setTimeout(() => setMensaje({ tipo: '', texto: '' }), 3500)
  }

  // ---- CREAR USUARIO ----
  const handleCrear = async (e) => {
    e.preventDefault()
    try {
      const res = await fetch('/flask/api/usuarios', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formCrear),
      })
      const data = await res.json()
      if (res.ok && data.success) {
        mostrarMensaje('success', 'Usuario creado correctamente')
        setModalCrear(false)
        setFormCrear({ nombre: '', correo: '', direccion: '', password: '', rol: 'usuario' })
        cargarUsuarios()
      } else {
        mostrarMensaje('error', data.error || 'Error al crear usuario')
      }
    } catch {
      mostrarMensaje('error', 'Error de conexión')
    }
  }

  // ---- ABRIR MODAL EDITAR ----
  const abrirEditar = (u) => {
    setFormEditar({ id: u.id, nombre: u.nombre, correo: u.correo, direccion: u.direccion || '', password: '', rol: u.rol })
    setModalEditar(true)
  }

  // ---- EDITAR USUARIO ----
  const handleEditar = async (e) => {
    e.preventDefault()
    try {
      const res = await fetch(`/flask/api/usuarios/${formEditar.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formEditar),
      })
      const data = await res.json()
      if (res.ok && data.success) {
        mostrarMensaje('success', 'Usuario actualizado correctamente')
        setModalEditar(false)
        cargarUsuarios()
      } else {
        mostrarMensaje('error', data.error || 'Error al actualizar')
      }
    } catch {
      mostrarMensaje('error', 'Error de conexión')
    }
  }

  // ---- ELIMINAR USUARIO ----
  const handleEliminar = async (id) => {
    if (!confirm('¿Seguro que deseas eliminar este usuario?')) return
    try {
      const res = await fetch(`/flask/api/usuarios/${id}`, { method: 'DELETE' })
      const data = await res.json()
      if (res.ok && data.success) {
        mostrarMensaje('success', 'Usuario eliminado')
        cargarUsuarios()
      } else {
        mostrarMensaje('error', data.error || 'Error al eliminar')
      }
    } catch {
      mostrarMensaje('error', 'Error de conexión')
    }
  }

  // ---- AUTORIZAR / DESAUTORIZAR ----
  const handleWhitelist = async (id, accion) => {
    try {
      const res = await fetch(`/flask/api/${accion}/${id}`, { method: 'POST' })
      const data = await res.json()
      if (res.ok && data.success) {
        mostrarMensaje('success', data.message)
        cargarUsuarios()
      } else {
        mostrarMensaje('error', data.error || 'Error')
      }
    } catch {
      mostrarMensaje('error', 'Error de conexión')
    }
  }

  if (status === 'loading' || loadingData) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
        <p>Cargando panel...</p>
      </div>
    )
  }

  return (
    <>
      <Navbar currentPage="admin" />

      <main style={{ flex: 1 }}>
        {/* BANNER */}
        <section className="banner-header-p1-index">
          <div className="banner-header">
            <div className="banner-header-text">
              <h1 className="banner-title-admin">
                Panel de <span>Administración</span>
              </h1>
              <div className="text-description-index">
                <hr />
                <p>
                  Bienvenido <strong>{session?.user?.name}</strong>.
                  Aquí puedes gestionar usuarios, roles y whitelist.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* MENSAJE FLASH */}
        {mensaje.texto && (
          <div style={{ maxWidth: 1100, margin: '16px auto', padding: '0 20px' }}>
            <div className={`flash-message ${mensaje.tipo}`}>{mensaje.texto}</div>
          </div>
        )}

        {/* TÍTULO SECCIÓN */}
        <section className="section">
          <div className="container-catalogo">
            <h3 className="title">USUARIOS REGISTRADOS</h3>
          </div>
        </section>

        {/* BOTÓN CREAR */}
        <div style={{ maxWidth: 1100, margin: '0 auto', padding: '0 20px 12px' }}>
          <button className="btn-crear" onClick={() => setModalCrear(true)}>
            <i className="fas fa-user-plus" style={{ marginRight: 8 }} />
            Crear nuevo usuario
          </button>
        </div>

        {/* TABLA */}
        <div className="admin-card">
          <table className="tabla-usuarios">
            <thead>
              <tr>
                <th>ID</th>
                <th>Nombre</th>
                <th>Correo</th>
                <th>Dirección</th>
                <th>Rol</th>
                <th>Whitelist</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              {usuarios.map((u) => {
                const esAdminPrincipal = u.correo === 'admin@olisport.com'
                return (
                  <tr key={u.id}>
                    <td>{u.id}</td>
                    <td>{u.nombre}</td>
                    <td>{u.correo}</td>
                    <td>{u.direccion || '—'}</td>
                    <td>
                      <span className={`badge ${u.rol}`}>{u.rol}</span>
                    </td>
                    <td>
                      {u.whitelist
                        ? <span className="badge ok">Autorizado ✔</span>
                        : <span className="badge no">No autorizado</span>
                      }
                    </td>
                    <td style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      {!esAdminPrincipal && (
                        <>
                          <button
                            className="btn-sm btn-edit"
                            onClick={() => abrirEditar(u)}
                          >
                            <i className="fas fa-edit" /> Editar
                          </button>

                          {u.whitelist ? (
                            <button
                              className="btn-sm btn-unauthorize"
                              onClick={() => handleWhitelist(u.id, 'desautorizar')}
                            >
                              <i className="fas fa-ban" /> Desautorizar
                            </button>
                          ) : (
                            <button
                              className="btn-sm btn-authorize"
                              onClick={() => handleWhitelist(u.id, 'autorizar')}
                            >
                              <i className="fas fa-check" /> Autorizar
                            </button>
                          )}

                          <button
                            className="btn-sm btn-delete"
                            onClick={() => handleEliminar(u.id)}
                          >
                            <i className="fas fa-trash" /> Eliminar
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* ===== MODAL CREAR USUARIO ===== */}
        {modalCrear && (
          <div className="modal-overlay" onClick={() => setModalCrear(false)}>
            <div className="modal-box" onClick={(e) => e.stopPropagation()}>
              <button className="modal-close" onClick={() => setModalCrear(false)}>✕</button>
              <h3><i className="fas fa-user-plus" style={{ marginRight: 8 }} />Crear Usuario</h3>
              <form onSubmit={handleCrear} className="modal-form">
                <label>Nombre</label>
                <input
                  type="text"
                  value={formCrear.nombre}
                  onChange={(e) => setFormCrear({ ...formCrear, nombre: e.target.value })}
                  required
                />
                <label>Correo</label>
                <input
                  type="email"
                  value={formCrear.correo}
                  onChange={(e) => setFormCrear({ ...formCrear, correo: e.target.value })}
                  required
                />
                <label>Dirección</label>
                <input
                  type="text"
                  value={formCrear.direccion}
                  onChange={(e) => setFormCrear({ ...formCrear, direccion: e.target.value })}
                />
                <label>Contraseña (por defecto: 12345)</label>
                <input
                  type="password"
                  value={formCrear.password}
                  onChange={(e) => setFormCrear({ ...formCrear, password: e.target.value })}
                  placeholder="Dejar vacío para usar 12345"
                />
                <label>Rol</label>
                <select
                  value={formCrear.rol}
                  onChange={(e) => setFormCrear({ ...formCrear, rol: e.target.value })}
                >
                  <option value="usuario">Usuario</option>
                  <option value="trabajador">Trabajador</option>
                  <option value="admin">Admin</option>
                </select>
                <button type="submit" className="btn-primary" style={{ marginTop: 8 }}>
                  Crear Usuario
                </button>
              </form>
            </div>
          </div>
        )}

        {/* ===== MODAL EDITAR USUARIO ===== */}
        {modalEditar && (
          <div className="modal-overlay" onClick={() => setModalEditar(false)}>
            <div className="modal-box" onClick={(e) => e.stopPropagation()}>
              <button className="modal-close" onClick={() => setModalEditar(false)}>✕</button>
              <h3><i className="fas fa-edit" style={{ marginRight: 8 }} />Editar Usuario</h3>
              <form onSubmit={handleEditar} className="modal-form">
                <label>Nombre</label>
                <input
                  type="text"
                  value={formEditar.nombre}
                  onChange={(e) => setFormEditar({ ...formEditar, nombre: e.target.value })}
                  required
                />
                <label>Correo</label>
                <input
                  type="email"
                  value={formEditar.correo}
                  onChange={(e) => setFormEditar({ ...formEditar, correo: e.target.value })}
                  required
                />
                <label>Dirección</label>
                <input
                  type="text"
                  value={formEditar.direccion}
                  onChange={(e) => setFormEditar({ ...formEditar, direccion: e.target.value })}
                />
                <label>Nueva contraseña (opcional)</label>
                <input
                  type="password"
                  value={formEditar.password}
                  onChange={(e) => setFormEditar({ ...formEditar, password: e.target.value })}
                  placeholder="Dejar vacío para no cambiar"
                />
                <label>Rol</label>
                <select
                  value={formEditar.rol}
                  onChange={(e) => setFormEditar({ ...formEditar, rol: e.target.value })}
                >
                  <option value="usuario">Usuario</option>
                  <option value="trabajador">Trabajador</option>
                  <option value="admin">Admin</option>
                </select>
                <button type="submit" className="btn-primary" style={{ marginTop: 8 }}>
                  Guardar Cambios
                </button>
              </form>
            </div>
          </div>
        )}
      </main>

      <Footer subtitle="Panel de Administración" />
    </>
  )
}
