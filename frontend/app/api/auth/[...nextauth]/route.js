import NextAuth from "next-auth"
import CredentialsProvider from "next-auth/providers/credentials"
import GoogleProvider from "next-auth/providers/google"

export const authOptions = {
  providers: [
    CredentialsProvider({
      name: "credentials",
      credentials: {
        correo: { label: "Correo", type: "email" },
        password: { label: "Contraseña", type: "password" },
      },
      async authorize(credentials) {
        try {
          const res = await fetch(`${process.env.FLASK_API_URL}/api/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              correo: credentials.correo,
              password: credentials.password,
            }),
          })
          const data = await res.json()
          if (res.ok && data.success) {
            return {
              id: data.user.id,
              name: data.user.nombre,
              email: data.user.correo,
              rol: data.user.rol,
              whitelist: data.user.whitelist,
              direccion: data.user.direccion,
            }
          }
          throw new Error(data.error || "Credenciales incorrectas")
        } catch (error) {
          throw new Error(error.message || "Error de conexión con el servidor")
        }
      },
    }),

    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      authorization: {
        params: {
          prompt: "select_account",
        },
      },
    }),
  ],

  callbacks: {
    async signIn({ user, account }) {
      if (account.provider === "google") {
        try {
          const res = await fetch(`${process.env.FLASK_API_URL}/api/google-login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              nombre: user.name,
              correo: user.email,
              provider: "google",
              provider_id: account.providerAccountId,
            }),
          })
          const data = await res.json()
          if (!res.ok || !data.success) return false
          user.id = data.user.id
          user.rol = data.user.rol
          user.whitelist = data.user.whitelist
          user.direccion = data.user.direccion
        } catch (error) {
          console.error("Error Google Login:", error)
          return false
        }
      }
      return true
    },

    async jwt({ token, user }) {
      if (user) {
        token.id = user.id
        token.rol = user.rol || "usuario"
        token.whitelist = user.whitelist || false
        token.direccion = user.direccion || null
      }
      return token
    },

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
    signIn: "/login",
    error: "/login",
  },

  session: {
    strategy: "jwt",
    maxAge: 60 * 60 * 24,
  },

  secret: process.env.NEXTAUTH_SECRET,
}

const handler = NextAuth(authOptions)
export { handler as GET, handler as POST }
