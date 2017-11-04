package tsec

import java.security.SecureRandom
import java.util.concurrent.atomic.LongAdder

import cats.evidence.Is
import org.bouncycastle.util.encoders.Hex
import tsec.common.TaggedString

package object csrf {

  protected val CSRFToken$$ : TaggedString = new TaggedString {
    type I = String
    val is: Is[I, String] = Is.refl[I]
  }

  type CSRFToken = CSRFToken$$.I

  object CSRFToken {

    @inline def is: Is[CSRFToken, String] = CSRFToken$$.is

    /** Cache our random, and seed it properly as per
      * https://tersesystems.com/2015/12/17/the-right-way-to-use-securerandom/
      */
    private val cachedRand: SecureRandom = {
      val r = new SecureRandom()
      r.nextBytes(new Array[Byte](20))
      r
    }

    /** We will keep a reference to how many times our random is utilized
      * After a sensible Integer.MaxValue/10 times, we should reseed, so roughly every 100 million tokens
      */
    private val adder: LongAdder = new LongAdder
    private val MaxBeforeReseed  = (Integer.MAX_VALUE / 10).toLong

    private def reSeed(): Unit = {
      adder.reset()
      cachedRand.nextBytes(new Array[Byte](20))
    }

    def apply(tokenLength: Int = 16): CSRFToken = {
      val tokenBytes = new Array[Byte](tokenLength)

      adder.increment()
      if (adder.sum() >= MaxBeforeReseed)
        reSeed()

      cachedRand.nextBytes(tokenBytes)
      is.flip.coerce(Hex.toHexString(tokenBytes))
    }
  }

}
