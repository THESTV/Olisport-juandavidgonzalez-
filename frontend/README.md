# 🚀 OliSport — Guía de Migración a Next.js

## Estructura del proyecto

```
📁 olisport-flask-api/     ← Backend Flask (API REST)
📁 olisport-nextjs/        ← Frontend Next.js (nuevo)
```

---

## 1️⃣ Configurar el Backend Flask

### Instalar dependencias
```bash
cd olisport-flask-api
pip install -r requirements.txt
```

### Iniciar el servidor Flask
```bash
python app.py
# El servidor corre en http://localhost:5000
```

---

## 2️⃣ Configurar el Frontend Next.js

### Instalar Node.js
Descarga Node.js 18+ desde https://nodejs.org

### Instalar dependencias
```bash
cd olisport-nextjs
npm install
```

### Configurar variables de entorno
Crea el archivo `.env.local` copiando `.env.example`:
```bash
cp .env.example .env.local
```

Edita `.env.local` con estos valores:
```env
NEXTAUTH_SECRET=una_cadena_muy_larga_y_segura_aqui_123456789
NEXTAUTH_URL=http://localhost:3000
FLASK_API_URL=http://localhost:5000
```

> Para generar un NEXTAUTH_SECRET seguro:
> ```bash
> openssl rand -base64 32
> ```

### Copiar imágenes
Copia las imágenes del proyecto original a la carpeta `public/` de Next.js:
```bash
# Desde la raíz del proyecto
cp -r Olisport-juandavidgonzalez--main/static/img/portfolio/* olisport-nextjs/public/portfolio/
cp Olisport-juandavidgonzalez--main/static/img/banneroli.webp olisport-nextjs/public/banner.webp
cp Olisport-juandavidgonzalez--main/static/img/portfolio/logo-olisport.PNG olisport-nextjs/public/logo-olisport.PNG
```

### Iniciar Next.js
```bash
cd olisport-nextjs
npm run dev
# La app corre en http://localhost:3000
```

---

## 3️⃣ Flujo de Autenticación

```
Usuario → /login (Next.js)
        → NextAuth llama a Flask /api/login
        → Flask verifica credenciales en Supabase
        → NextAuth crea sesión JWT con rol del usuario
        → Redirección según rol:
             admin     → /admin
             trabajador → /trabajador  
             usuario    → /market
```

---

## 4️⃣ Páginas disponibles

| Ruta          | Descripción                          | Protección       |
|---------------|--------------------------------------|------------------|
| `/`           | Página principal con catálogo        | Pública          |
| `/login`      | Iniciar sesión                       | Pública          |
| `/register`   | Crear cuenta                         | Pública          |
| `/market`     | Market con filtros y búsqueda        | Requiere login   |
| `/perfil`     | Editar datos personales              | Requiere login   |
| `/admin`      | Gestión de usuarios (CRUD completo)  | Solo admin       |
| `/trabajador` | Panel de trabajo                     | Trabajador+admin |
| `/about`      | Quiénes somos                        | Pública          |
| `/servicio`   | Servicios                            | Pública          |
| `/contact`    | Contacto                             | Pública          |

---

## 5️⃣ Endpoints del API Flask

| Método | Ruta                          | Descripción              |
|--------|-------------------------------|--------------------------|
| POST   | `/api/login`                  | Login (usado por NextAuth)|
| POST   | `/api/register`               | Crear cuenta             |
| PUT    | `/api/perfil`                 | Actualizar perfil        |
| GET    | `/api/usuarios`               | Listar usuarios (admin)  |
| POST   | `/api/usuarios`               | Crear usuario (admin)    |
| PUT    | `/api/usuarios/<id>`          | Editar usuario (admin)   |
| DELETE | `/api/usuarios/<id>`          | Eliminar usuario (admin) |
| POST   | `/api/autorizar/<id>`         | Agregar a whitelist      |
| POST   | `/api/desautorizar/<id>`      | Quitar de whitelist      |
| GET    | `/api/productos`              | Listar productos         |

---

## 6️⃣ Credenciales de prueba

```
Admin:    admin@olisport.com / 12345
```

---

## 7️⃣ Deploy en producción

**Next.js → Vercel**
1. Sube el código a GitHub
2. Importa el repo en vercel.com
3. Agrega las variables de entorno en Vercel

**Flask → Railway o Render**
1. Sube `olisport-flask-api/` a un repo
2. Conecta en railway.app o render.com
3. Actualiza `FLASK_API_URL` en Vercel con la URL pública de Railway
