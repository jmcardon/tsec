package tsec

import cats.data.OptionT
import cats.evidence.Is
import org.bouncycastle.util.encoders.Hex
import org.http4s.{Request, Response}
import org.http4s.server.Middleware
import tsec.common.{ManagedRandom, StringNewt}

package object csrf {

  protected val CSRFToken$$ : StringNewt = new StringNewt {
    type I = String
    val is: Is[I, String] = Is.refl[I]
  }

  type CSRFToken = CSRFToken$$.I

  object CSRFToken extends ManagedRandom {

    @inline def is: Is[CSRFToken, String] = CSRFToken$$.is

    def apply(s: String): CSRFToken = is.flip.coerce(s)

    def generateHexBase(tokenLength: Int = 32): String = {
      val tokenBytes = new Array[Byte](tokenLength)
      nextBytes(tokenBytes)
      Hex.toHexString(tokenBytes)
    }
  }

  type CSRFMiddleware[F[_]] =
    Middleware[OptionT[F, ?], Request[F], Response[F], Request[F], Response[F]]

}
