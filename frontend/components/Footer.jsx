export default function Footer({ subtitle = 'Catálogo 2025' }) {
  return (
    <footer className="main-footer">
      <p>&copy; 2025 OliSport — Todos los derechos reservados.</p>
      <div className="container">
        <p className="small">{subtitle}</p>
        <ul>
          <li><a href="#"><i className="fab fa-facebook" /></a></li>
          <li><a href="#"><i className="fab fa-instagram" /></a></li>
          <li><a href="#"><i className="fab fa-youtube" /></a></li>
        </ul>
      </div>
    </footer>
  )
}
