import User from "@/models/User";
import { NextAuthOptions } from "next-auth";
import CredentialsContainer from "next-auth/providers/credentials";
import { dbConnect } from "./db";
import bcrypt from "bcryptjs";

export const authOptions: NextAuthOptions = {
    providers: [
        CredentialsContainer({
            name: "Credentials",
            credentials: {
                email: { label: "Email", type: "email", placeholder: "Email" },
                password: { label: "Password", type: "password" },
            },
            async authorize(credentials) {
                const { email, password } = credentials || {};

                if (!email || !password) {
                    throw new Error("Email and password are required");
                }

                try {
                    await dbConnect();
                    const user = await User.findOne({ email });
                    if (!user) {
                        throw new Error("User not found");
                    }

                    const isValidPassword = await bcrypt.compare(password, user.password);
                    if (!isValidPassword) {
                        throw new Error("Invalid password");
                    }

                    return { id: user._id.toString(), email: user.email };
                } catch (error) {
                    console.error("Authorization error:", error);
                    throw new Error("Internal server error");
                }
            },
        })
      ],
      callbacks: {
        async jwt({ token, user }) {
            if (user) {
                token.id = user.id;
                token.email = user.email;
            }
            return token;
        },
        async session({ session, token }) {
            if (session.user) {
                session.user.id = token.id as string;
            }
            return session;
        },
      },
    pages: {
        signIn: "/login",
        error: "/login", // Error code passed in query string as ?error=
      },
    session: {
        strategy: "jwt",
        maxAge: 30 * 24 * 60 * 60, // 30 days
    },
    secret: process.env.NEXTAUTH_SECRET
};
