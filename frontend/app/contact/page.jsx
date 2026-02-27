'use client'
import { useState } from 'react'
import Navbar from '@/components/Navbar'
import Footer from '@/components/Footer'

export default function ContactPage() {
  const [form, setForm] = useState({ nombre: '', correo: '', asunto: '', mensaje: '' })
  const [enviado, setEnviado] = useState(false)

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value })

  const handleSubmit = (e) => {
    e.preventDefault()
    // Aquí puedes conectar con un servicio de email (EmailJS, Formspree, etc.)
    setEnviado(true)
    setForm({ nombre: '', correo: '', asunto: '', mensaje: '' })
    setTimeout(() => setEnviado(false), 4000)
  }

  return (
    <>
      <Navbar currentPage="contact" />
      <main style={{ flex: 1 }}>
        <section className="banner-header-p1-index">
          <div className="banner-header">
            <h1 className="banner-title-admin">Contác<span>tanos</span></h1>
          </div>
        </section>

        <section style={{ maxWidth: 900, margin: '0 auto', padding: '40px 24px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 48 }}>
          {/* INFO */}
          <div>
            <h2 style={{ color: 'rgb(0,229,255)', marginBottom: 24 }}>¡Hablemos!</h2>
            <p style={{ color: 'rgba(255,255,255,0.75)', marginBottom: 32 }}>
              Estamos aquí para ayudarte. Si tienes preguntas sobre productos, tallas,
              envíos o cualquier otra consulta, no dudes en escribirnos.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {[
                { icono: 'fas fa-map-marker-alt', texto: 'Cali, Valle del Cauca, Colombia' },
                { icono: 'fab fa-whatsapp', texto: '+57 310 000 0000' },
                { icono: 'fas fa-envelope', texto: 'olisport@gmail.com' },
                { icono: 'fas fa-clock', texto: 'Lun – Sáb: 8am – 6pm' },
              ].map((item, i) => (
                <div key={i} style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                  <i className={item.icono} style={{ color: 'rgb(0,229,255)', marginTop: 4, fontSize: '1.1rem', width: 20 }} />
                  <span style={{ color: 'rgba(255,255,255,0.75)' }}>{item.texto}</span>
                </div>
              ))}
            </div>
          </div>

          {/* FORMULARIO */}
          <div>
            {enviado && (
              <div className="flash-message success" style={{ marginBottom: 16 }}>
                ✅ ¡Mensaje enviado! Te responderemos pronto.
              </div>
            )}
            <form onSubmit={handleSubmit} className="contact-form">
              <input
                type="text" name="nombre" placeholder="Tu nombre"
                value={form.nombre} onChange={handleChange} required
              />
              <input
                type="email" name="correo" placeholder="Tu correo"
                value={form.correo} onChange={handleChange} required
              />
              <input
                type="text" name="asunto" placeholder="Asunto"
                value={form.asunto} onChange={handleChange} required
              />
              <textarea
                name="mensaje" placeholder="Tu mensaje..."
                rows={5} value={form.mensaje} onChange={handleChange} required
              />
              <button type="submit" className="btn" style={{ color: '#030344' }}>
                <i className="fas fa-paper-plane" style={{ marginRight: 8 }} />
                Enviar mensaje
              </button>
            </form>
          </div>
        </section>
      </main>
      <Footer subtitle="Contáctanos" />
    </>
  )
}
