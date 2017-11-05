package tsec

import java.security.SecureRandom
import java.util.concurrent.atomic.LongAdder

import cats.evidence.Is
import org.bouncycastle.util.encoders.Hex
import tsec.common.{ManagedRandom, TaggedString}

package object csrf {

  protected val CSRFToken$$ : TaggedString = new TaggedString {
    type I = String
    val is: Is[I, String] = Is.refl[I]
  }

  type CSRFToken = CSRFToken$$.I

  object CSRFToken extends ManagedRandom {

    @inline def is: Is[CSRFToken, String] = CSRFToken$$.is

    def apply(s: String): CSRFToken = is.flip.coerce(s)

    def generateHexBase(tokenLength: Int = 16): String = {
      val tokenBytes = new Array[Byte](tokenLength)
      nextBytes(tokenBytes)
      Hex.toHexString(tokenBytes)
    }
  }

}
