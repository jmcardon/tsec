package tsec

import cats.data.OptionT
import cats.evidence.Is
import org.bouncycastle.util.encoders.Hex
import org.http4s.{Request, Response}
import org.http4s.server.Middleware
import tsec.common.{ManagedRandom, StringNewt}

package object csrf {

  type CSRFToken = CSRFToken.Token

  object CSRFToken extends ManagedRandom {
    type Token <: String

    def apply(s: String): CSRFToken   = s.asInstanceOf[CSRFToken]
    def subst[F[_]](value: F[String]): F[CSRFToken] = value.asInstanceOf[F[CSRFToken]]

    def generateHexBase(tokenLength: Int = 32): String = {
      val tokenBytes = new Array[Byte](tokenLength)
      nextBytes(tokenBytes)
      Hex.toHexString(tokenBytes)
    }
  }

  type CSRFMiddleware[F[_]] =
    Middleware[OptionT[F, ?], Request[F], Response[F], Request[F], Response[F]]

}
