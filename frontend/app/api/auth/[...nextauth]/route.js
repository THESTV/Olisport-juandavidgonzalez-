import NextAuth from 'next-auth'
import CredentialsProvider from 'next-auth/providers/credentials'

export const authOptions = {
  providers: [
    CredentialsProvider({
      name: 'credentials',
      credentials: {
        correo: { label: 'Correo', type: 'email' },
        password: { label: 'Contraseña', type: 'password' },
      },
      async authorize(credentials) {
        try {
          // Llama al endpoint de login del backend Flask
          const res = await fetch(`${process.env.FLASK_API_URL}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              correo: credentials.correo,
              password: credentials.password,
            }),
          })

          const data = await res.json()

          if (res.ok && data.success) {
            // Devuelve el usuario con todos los datos necesarios
            return {
              id: data.user.id,
              name: data.user.nombre,
              email: data.user.correo,
              rol: data.user.rol,
              whitelist: data.user.whitelist,
              direccion: data.user.direccion,
            }
          }

          // Si el login falla, lanza el mensaje de error de Flask
          throw new Error(data.error || 'Credenciales incorrectas')
        } catch (error) {
          throw new Error(error.message || 'Error de conexión con el servidor')
        }
      },
    }),
  ],

  callbacks: {
    // Agrega los datos personalizados (rol, whitelist) al token JWT
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id
        token.rol = user.rol
        token.whitelist = user.whitelist
        token.direccion = user.direccion
      }
      return token
    },
    // Expone los datos del token a la sesión del cliente
    async session({ session, token }) {
      if (token) {
        session.user.id = token.id
        session.user.rol = token.rol
        session.user.whitelist = token.whitelist
        session.user.direccion = token.direccion
      }
      return session
    },
  },

  pages: {
    signIn: '/login',
    error: '/login',
  },

  session: {
    strategy: 'jwt',
    maxAge: 60 * 60 * 24, // 24 horas
  },

  secret: process.env.NEXTAUTH_SECRET,
}

const handler = NextAuth(authOptions)
export { handler as GET, handler as POST }
