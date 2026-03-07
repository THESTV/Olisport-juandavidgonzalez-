'use client'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { useState, useEffect } from 'react'
import Navbar from '@/components/Navbar'
import Footer from '@/components/Footer'

export default function AdminPage() {
  const { data: session, status } = useSession()
  const router = useRouter()

  const [tab, setTab] = useState('usuarios')
  const [usuarios, setUsuarios] = useState([])
  const [roles, setRoles] = useState([])
  const [loadingData, setLoadingData] = useState(true)
  const [mensaje, setMensaje] = useState({ tipo: '', texto: '' })

  // Filtros
  const [filtroRol, setFiltroRol] = useState('todos')
  const [filtroAuth, setFiltroAuth] = useState('todos')

  const [modalCrear, setModalCrear] = useState(false)
  const [formCrear, setFormCrear] = useState({ nombre: '', correo: '', direccion: '', password: '', rol: 'usuario' })

  const [modalEditar, setModalEditar] = useState(false)
  const [formEditar, setFormEditar] = useState({ id: '', nombre: '', correo: '', direccion: '', password: '', rol: '' })

  const [modalEditarRol, setModalEditarRol] = useState(false)
  const [formEditarRol, setFormEditarRol] = useState({ id: '', nombre: '', permisos: {} })

  useEffect(() => {
    if (status === 'unauthenticated') router.push('/login')
    if (status === 'authenticated' && session?.user?.rol !== 'admin') router.push('/market')
  }, [status, session, router])

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

  const cargarRoles = async () => {
    try {
      const res = await fetch('/flask/api/roles')
      const data = await res.json()
      setRoles(data.roles || [])
    } catch {}
  }

  useEffect(() => {
    if (status === 'authenticated' && session?.user?.rol === 'admin') {
      cargarUsuarios()
      cargarRoles()
    }
  }, [status, session])

  const mostrarMensaje = (tipo, texto) => {
    setMensaje({ tipo, texto })
    setTimeout(() => setMensaje({ tipo: '', texto: '' }), 3500)
  }

  const handleCrear = async (e) => {
    e.preventDefault()
    try {
      const res = await fetch('/flask/api/usuarios', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formCrear),
      })
      const data = await res.json()
      if (res.ok && data.success) {
        mostrarMensaje('success', 'Usuario creado correctamente')
        setModalCrear(false)
        setFormCrear({ nombre: '', correo: '', direccion: '', password: '', rol: 'usuario' })
        cargarUsuarios()
      } else { mostrarMensaje('error', data.error || 'Error al crear usuario') }
    } catch { mostrarMensaje('error', 'Error de conexión') }
  }

  const abrirEditar = (u) => {
    setFormEditar({ id: u.id, nombre: u.nombre, correo: u.correo, direccion: u.direccion || '', password: '', rol: u.rol })
    setModalEditar(true)
  }

  const handleEditar = async (e) => {
    e.preventDefault()
    try {
      const res = await fetch(`/flask/api/usuarios/${formEditar.id}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formEditar),
      })
      const data = await res.json()
      if (res.ok && data.success) {
        mostrarMensaje('success', 'Usuario actualizado correctamente')
        setModalEditar(false)
        cargarUsuarios()
      } else { mostrarMensaje('error', data.error || 'Error al actualizar') }
    } catch { mostrarMensaje('error', 'Error de conexión') }
  }

  const handleEliminar = async (id) => {
    if (!confirm('¿Seguro que deseas eliminar este usuario?')) return
    try {
      const res = await fetch(`/flask/api/usuarios/${id}`, { method: 'DELETE' })
      const data = await res.json()
      if (res.ok && data.success) { mostrarMensaje('success', 'Usuario eliminado'); cargarUsuarios() }
      else { mostrarMensaje('error', data.error || 'Error al eliminar') }
    } catch { mostrarMensaje('error', 'Error de conexión') }
  }

  const handleWhitelist = async (id, accion) => {
    try {
      const res = await fetch(`/flask/api/${accion}/${id}`, { method: 'POST' })
      const data = await res.json()
      if (res.ok && data.success) { mostrarMensaje('success', data.message); cargarUsuarios() }
      else { mostrarMensaje('error', data.error || 'Error') }
    } catch { mostrarMensaje('error', 'Error de conexión') }
  }

  const abrirEditarRol = (r) => {
    setFormEditarRol({ id: r.id, nombre: r.nombre, permisos: { ...r.permisos } })
    setModalEditarRol(true)
  }

  const handleEditarRol = async (e) => {
    e.preventDefault()
    try {
      const res = await fetch(`/flask/api/roles/${formEditarRol.id}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nombre: formEditarRol.nombre, permisos: formEditarRol.permisos }),
      })
      const data = await res.json()
      if (res.ok && data.success) {
        mostrarMensaje('success', 'Permisos actualizados')
        setModalEditarRol(false)
        cargarRoles()
      } else { mostrarMensaje('error', data.error || 'Error') }
    } catch { mostrarMensaje('error', 'Error de conexión') }
  }

  const textoWhitelist = (u) => {
    if (u.rol === 'trabajador') return u.whitelist ? 'Acceso a reportes' : 'Sin acceso a reportes'
    if (u.rol === 'usuario') return u.whitelist ? 'Acceso al market' : 'Sin acceso al market'
    return u.whitelist ? 'Autorizado' : 'No autorizado'
  }

  // Stats
  const totalAdmin       = usuarios.filter(u => u.rol === 'admin').length
  const totalTrabajadores = usuarios.filter(u => u.rol === 'trabajador').length
  const totalUsuarios    = usuarios.filter(u => u.rol === 'usuario').length
  const totalAutorizados = usuarios.filter(u => u.whitelist).length

  // Filtrado
  const usuariosFiltrados = usuarios.filter(u => {
    const porRol  = filtroRol  === 'todos' || u.rol === filtroRol
    const porAuth = filtroAuth === 'todos' || (filtroAuth === 'si' ? u.whitelist : !u.whitelist)
    return porRol && porAuth
  })

  const permisosLabel = { usuarios: 'Gestión usuarios', productos: 'Productos', reportes: 'Reportes', roles: 'Gestión roles' }
  const rolIcon  = { admin: 'fa-crown', trabajador: 'fa-tools', usuario: 'fa-user' }
  const rolColor = { admin: '#f59e0b', trabajador: '#06b6d4', usuario: '#8b5cf6' }

  if (status === 'loading' || loadingData) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
        <div style={{ textAlign: 'center' }}>
          <div className="spinner" />
          <p style={{ color: 'rgba(255,255,255,0.5)' }}>Cargando panel...</p>
        </div>
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
                <p>Bienvenido <strong>{session?.user?.name}</strong>. Gestiona usuarios, roles y autorizaciones.</p>
              </div>
            </div>
          </div>
        </section>

        <div className="admin-wrap">

          {/* FLASH */}
          {mensaje.texto && (
            <div className={`flash ${mensaje.tipo}`} style={{ marginTop: 24 }}>
              <i className={`fas fa-${mensaje.tipo === 'success' ? 'check-circle' : 'exclamation-circle'}`} />
              {mensaje.texto}
            </div>
          )}

          {/* STATS */}
          <div className="stats-grid">
            {[
              { label: 'Admins',       value: totalAdmin,         color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', icon: 'fa-crown',        filtro: () => { setFiltroRol('admin');      setFiltroAuth('todos'); setTab('usuarios') } },
              { label: 'Trabajadores', value: totalTrabajadores,  color: '#06b6d4', bg: 'rgba(6,182,212,0.12)',  icon: 'fa-tools',        filtro: () => { setFiltroRol('trabajador'); setFiltroAuth('todos'); setTab('usuarios') } },
              { label: 'Usuarios',     value: totalUsuarios,      color: '#8b5cf6', bg: 'rgba(139,92,246,0.12)', icon: 'fa-user',         filtro: () => { setFiltroRol('usuario');    setFiltroAuth('todos'); setTab('usuarios') } },
              { label: 'Autorizados',  value: totalAutorizados,   color: '#10b981', bg: 'rgba(16,185,129,0.12)', icon: 'fa-check-circle', filtro: () => { setFiltroRol('todos');      setFiltroAuth('si');    setTab('usuarios') } },
            ].map(s => (
              <div
                className="stat-card"
                key={s.label}
                onClick={s.filtro}
                style={{ cursor: 'pointer' }}
                title={`Filtrar por ${s.label}`}
              >
                <div className="stat-icon" style={{ background: s.bg }}>
                  <i className={`fas ${s.icon}`} style={{ color: s.color }} />
                </div>
                <div>
                  <div className="stat-num">{s.value}</div>
                  <div className="stat-label">{s.label}</div>
                </div>
              </div>
            ))}
          </div>

          {/* TABS */}
          <div className="tabs-bar">
            {[
              { key: 'usuarios', label: 'Usuarios',   icon: 'fa-users' },
              { key: 'roles',    label: 'Roles RBAC', icon: 'fa-shield-alt' },
            ].map(t => (
              <button key={t.key} className={`tab-btn ${tab === t.key ? 'active' : ''}`} onClick={() => setTab(t.key)}>
                <i className={`fas ${t.icon}`} style={{ marginRight: 7 }} />{t.label}
              </button>
            ))}
          </div>

          {/* ===== TAB USUARIOS ===== */}
          {tab === 'usuarios' && (
            <div>
              <button className="btn-nuevo" onClick={() => setModalCrear(true)}>
                <i className="fas fa-user-plus" /> Nuevo usuario
              </button>

              <div className="card-tabla">
                <div className="card-tabla-header">
                  {/* Contador */}
                  <span className="card-tabla-title">
                    <i className="fas fa-users" style={{ marginRight: 8 }} />
                    {usuariosFiltrados.length} de {usuarios.length} usuarios
                  </span>

                  {/* Filtros */}
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                    <select
                      value={filtroRol}
                      onChange={e => setFiltroRol(e.target.value)}
                      className="field-select"
                      style={{ padding: '6px 12px', fontSize: '0.82rem' }}
                    >
                      <option value="todos">Todos los roles</option>
                      <option value="admin">Admin</option>
                      <option value="trabajador">Trabajador</option>
                      <option value="usuario">Usuario</option>
                    </select>
                    <select
                      value={filtroAuth}
                      onChange={e => setFiltroAuth(e.target.value)}
                      className="field-select"
                      style={{ padding: '6px 12px', fontSize: '0.82rem' }}
                    >
                      <option value="todos">Toda autorización</option>
                      <option value="si">Autorizados ✔</option>
                      <option value="no">Sin autorización ✘</option>
                    </select>
                    {/* Botón limpiar filtros */}
                    {(filtroRol !== 'todos' || filtroAuth !== 'todos') && (
                      <button
                        onClick={() => { setFiltroRol('todos'); setFiltroAuth('todos') }}
                        style={{
                          padding: '6px 12px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.15)',
                          background: 'transparent', color: 'rgba(255,255,255,0.45)',
                          fontSize: '0.78rem', cursor: 'pointer', fontFamily: 'Raleway, sans-serif',
                          display: 'flex', alignItems: 'center', gap: 5,
                        }}
                        title="Limpiar filtros"
                      >
                        <i className="fas fa-times" /> Limpiar
                      </button>
                    )}
                  </div>
                </div>

                <div style={{ overflowX: 'auto' }}>
                  <table className="tabla-pro">
                    <thead>
                      <tr>
                        <th>Usuario</th>
                        <th>Correo</th>
                        <th>Dirección</th>
                        <th>Rol</th>
                        <th>Autorización</th>
                        <th>Acciones</th>
                      </tr>
                    </thead>
                    <tbody>
                      {usuariosFiltrados.length === 0 ? (
                        <tr>
                          <td colSpan={6} style={{ textAlign: 'center', padding: 32, color: 'rgba(255,255,255,0.3)' }}>
                            <i className="fas fa-search" style={{ marginRight: 8 }} />
                            No hay usuarios con ese filtro
                          </td>
                        </tr>
                      ) : (
                        usuariosFiltrados.map((u) => {
                          const esAdmin = u.correo === 'admin@olisport.com'
                          const inicial = u.nombre?.charAt(0).toUpperCase() || '?'
                          const avatarColor = rolColor[u.rol] || '#888'
                          return (
                            <tr key={u.id}>
                              <td>
                                <div className="u-name">
                                  <div className="u-avatar" style={{ background: `${avatarColor}22`, color: avatarColor }}>
                                    {inicial}
                                  </div>
                                  <span style={{ fontWeight: 600 }}>{u.nombre}</span>
                                </div>
                              </td>
                              <td style={{ color: 'rgba(255,255,255,0.5)' }}>{u.correo}</td>
                              <td style={{ color: 'rgba(255,255,255,0.4)', fontSize: '0.82rem' }}>{u.direccion || '—'}</td>
                              <td>
                                <span className={`rol-badge ${u.rol}`}>
                                  <i className={`fas ${rolIcon[u.rol] || 'fa-user'}`} />
                                  {u.rol}
                                </span>
                              </td>
                              <td>
                                <span className={`auth-badge ${u.whitelist ? 'si' : 'no'}`}>
                                  <i className={`fas fa-${u.whitelist ? 'check-circle' : 'minus-circle'}`} />
                                  {textoWhitelist(u)}
                                </span>
                              </td>
                              <td>
                                {!esAdmin && (
                                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                                    <button className="btn-accion editar" onClick={() => abrirEditar(u)}>
                                      <i className="fas fa-edit" /> Editar
                                    </button>
                                    {u.whitelist ? (
                                      <button className="btn-accion desautorizar" onClick={() => handleWhitelist(u.id, 'desautorizar')}>
                                        <i className="fas fa-ban" /> Revocar
                                      </button>
                                    ) : (
                                      <button className="btn-accion autorizar" onClick={() => handleWhitelist(u.id, 'autorizar')}>
                                        <i className="fas fa-check" /> Autorizar
                                      </button>
                                    )}
                                    <button className="btn-accion eliminar" onClick={() => handleEliminar(u.id)}>
                                      <i className="fas fa-trash" />
                                    </button>
                                  </div>
                                )}
                              </td>
                            </tr>
                          )
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ===== TAB ROLES ===== */}
          {tab === 'roles' && (
            <div>
              <div className="roles-cards">
                {[
                  { rol: 'admin',      icon: '👑', desc: 'Acceso total al sistema. Gestiona usuarios, roles y autorizaciones.' },
                  { rol: 'trabajador', icon: '🔧', desc: 'Accede a reportes solo si el admin le otorga autorización (whitelist).' },
                  { rol: 'usuario',    icon: '🛒', desc: 'Accede al market y catálogo solo si el admin lo autoriza (whitelist).' },
                ].map(({ rol, icon, desc }) => (
                  <div key={rol} className={`rol-card ${rol}`}>
                    <div className="rol-card-icon">{icon}</div>
                    <div className="rol-card-nombre" style={{ color: rolColor[rol] }}>{rol}</div>
                    <div className="rol-card-desc">{desc}</div>
                  </div>
                ))}
              </div>

              <div className="card-tabla">
                <div className="card-tabla-header">
                  <span className="card-tabla-title">
                    <i className="fas fa-shield-alt" style={{ marginRight: 8 }} />
                    Permisos por rol
                  </span>
                </div>
                <div style={{ overflowX: 'auto' }}>
                  <table className="tabla-pro">
                    <thead>
                      <tr>
                        <th>Rol</th>
                        {Object.values(permisosLabel).map(l => <th key={l}>{l}</th>)}
                        <th>Acciones</th>
                      </tr>
                    </thead>
                    <tbody>
                      {roles.map((r) => (
                        <tr key={r.id}>
                          <td>
                            <span className={`rol-badge ${r.nombre}`}>
                              <i className={`fas ${rolIcon[r.nombre] || 'fa-circle'}`} />
                              {r.nombre}
                            </span>
                          </td>
                          {Object.keys(permisosLabel).map(k => (
                            <td key={k}>
                              <span className={`permiso-pill ${r.permisos?.[k] ? 'on' : 'off'}`}>
                                {r.permisos?.[k] ? '✔' : '✘'}
                              </span>
                            </td>
                          ))}
                          <td>
                            <button className="btn-accion permisos" onClick={() => abrirEditarRol(r)}>
                              <i className="fas fa-sliders-h" /> Editar permisos
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

        </div>{/* fin admin-wrap */}
      </main>

      {/* ===== MODAL CREAR USUARIO ===== */}
      {modalCrear && (
        <div className="modal-bg" onClick={() => setModalCrear(false)}>
          <div className="modal-panel" onClick={e => e.stopPropagation()}>
            <button className="modal-close-btn" onClick={() => setModalCrear(false)}>✕</button>
            <div className="modal-title">
              <i className="fas fa-user-plus" style={{ color: 'rgb(0,229,255)' }} /> Crear Usuario
            </div>
            <form onSubmit={handleCrear}>
              {[['Nombre','text','nombre'],['Correo','email','correo'],['Dirección','text','direccion']].map(([label,type,key]) => (
                <div className="field-group" key={key}>
                  <label className="field-label">{label}</label>
                  <input className="field-input" type={type} value={formCrear[key]}
                    onChange={e => setFormCrear({ ...formCrear, [key]: e.target.value })}
                    required={key !== 'direccion'} />
                </div>
              ))}
              <div className="field-group">
                <label className="field-label">Contraseña (por defecto: 12345)</label>
                <input className="field-input" type="password" value={formCrear.password}
                  onChange={e => setFormCrear({ ...formCrear, password: e.target.value })}
                  placeholder="Vacío = 12345" />
              </div>
              <div className="field-group">
                <label className="field-label">Rol</label>
                <select className="field-select" value={formCrear.rol}
                  onChange={e => setFormCrear({ ...formCrear, rol: e.target.value })}>
                  {roles.map(r => <option key={r.id} value={r.nombre}>{r.nombre}</option>)}
                </select>
              </div>
              <button type="submit" className="btn-submit">Crear Usuario</button>
            </form>
          </div>
        </div>
      )}

      {/* ===== MODAL EDITAR USUARIO ===== */}
      {modalEditar && (
        <div className="modal-bg" onClick={() => setModalEditar(false)}>
          <div className="modal-panel" onClick={e => e.stopPropagation()}>
            <button className="modal-close-btn" onClick={() => setModalEditar(false)}>✕</button>
            <div className="modal-title">
              <i className="fas fa-edit" style={{ color: 'rgb(0,229,255)' }} /> Editar Usuario
            </div>
            <form onSubmit={handleEditar}>
              {[['Nombre','text','nombre'],['Correo','email','correo'],['Dirección','text','direccion']].map(([label,type,key]) => (
                <div className="field-group" key={key}>
                  <label className="field-label">{label}</label>
                  <input className="field-input" type={type} value={formEditar[key]}
                    onChange={e => setFormEditar({ ...formEditar, [key]: e.target.value })}
                    required={key !== 'direccion'} />
                </div>
              ))}
              <div className="field-group">
                <label className="field-label">Nueva contraseña (opcional)</label>
                <input className="field-input" type="password" value={formEditar.password}
                  onChange={e => setFormEditar({ ...formEditar, password: e.target.value })}
                  placeholder="Vacío = sin cambios" />
              </div>
              <div className="field-group">
                <label className="field-label">Rol</label>
                <select className="field-select" value={formEditar.rol}
                  onChange={e => setFormEditar({ ...formEditar, rol: e.target.value })}>
                  {roles.map(r => <option key={r.id} value={r.nombre}>{r.nombre}</option>)}
                </select>
              </div>
              <button type="submit" className="btn-submit">Guardar Cambios</button>
            </form>
          </div>
        </div>
      )}

      {/* ===== MODAL EDITAR ROL ===== */}
      {modalEditarRol && (
        <div className="modal-bg" onClick={() => setModalEditarRol(false)}>
          <div className="modal-panel" onClick={e => e.stopPropagation()}>
            <button className="modal-close-btn" onClick={() => setModalEditarRol(false)}>✕</button>
            <div className="modal-title">
              <i className="fas fa-shield-alt" style={{ color: 'rgb(0,229,255)' }} />
              Permisos —&nbsp;
              <span className={`rol-badge ${formEditarRol.nombre}`}>{formEditarRol.nombre}</span>
            </div>
            <form onSubmit={handleEditarRol}>
              <div style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 12, padding: '4px 16px', marginBottom: 16 }}>
                {Object.keys(permisosLabel).map(p => (
                  <label key={p} className="check-row">
                    <input type="checkbox" checked={formEditarRol.permisos[p] || false}
                      onChange={e => setFormEditarRol({ ...formEditarRol, permisos: { ...formEditarRol.permisos, [p]: e.target.checked } })} />
                    <span>{permisosLabel[p]}</span>
                  </label>
                ))}
              </div>
              <button type="submit" className="btn-submit">Guardar permisos</button>
            </form>
          </div>
        </div>
      )}

      <Footer subtitle="Panel de Administración" />
    </>
  )
}