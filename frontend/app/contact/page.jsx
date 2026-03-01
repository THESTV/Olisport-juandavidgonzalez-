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

    <section style={{ maxWidth: 900, margin: '0 auto', padding: '40px 24px' }}>
      
      {/* INFO + FORMULARIO en 2 columnas */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 48, marginBottom: 48 }}>
        
        {/* INFO */}
        <div>
          <h2 style={{ color: 'rgb(0,229,255)', marginBottom: 24 }}>¡Hablemos!</h2>
          <p style={{ color: 'rgba(255,255,255,0.75)', marginBottom: 32 }}>
            Estamos aquí para ayudarte. Si tienes preguntas sobre productos, tallas,
            envíos o cualquier otra consulta, no dudes en escribirnos.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {[
              { icono: 'fas fa-map-marker-alt', texto: 'Cra. 6 #13-2, Cali, Valle del Cauca' },
              { icono: 'fab fa-whatsapp', texto: '+57 321 597 9188' },
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
            <input type="text" name="nombre" placeholder="Tu nombre"
              value={form.nombre} onChange={handleChange} required />
            <input type="email" name="correo" placeholder="Tu correo"
              value={form.correo} onChange={handleChange} required />
            <input type="text" name="asunto" placeholder="Asunto"
              value={form.asunto} onChange={handleChange} required />
            <textarea name="mensaje" placeholder="Tu mensaje..."
              rows={5} value={form.mensaje} onChange={handleChange} required />
            <button type="submit" className="btn" style={{ color: '#030344' }}>
              <i className="fas fa-paper-plane" style={{ marginRight: 8 }} />
              Enviar mensaje
            </button>
          </form>
        </div>
      </div>

      {/* MAPA — ancho completo debajo */}
      <div style={{ borderRadius: 12, overflow: 'hidden', border: '1px solid rgba(0,229,255,0.2)' }}>
        <iframe
          src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d882.8!2d-76.5307922!3d3.4511355!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x8e30a7002f621329:0x43476b9bc4923696!2sOliSport!5e0!3m2!1ses!2sco!4v1709000000000!5m2!1ses!2sco"          width="100%"
          height="320"
          style={{ border: 0, display: 'block' }}
          allowFullScreen=""
          loading="lazy"
          referrerPolicy="no-referrer-when-downgrade"
        />
      </div>

    </section>      </main>
      <Footer subtitle="Contáctanos" />
    </>
  )
}
