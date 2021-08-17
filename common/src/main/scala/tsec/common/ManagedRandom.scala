package tsec.common

import java.security.SecureRandom

/** A trait that manages a secureRandom instance.
  */
trait ManagedRandom {

  /** Cache our random, and seed it properly as per
    * [[https://tersesystems.com/2015/12/17/the-right-way-to-use-securerandom/]]
    */
  private[tsec] val cachedRand: SecureRandom = {
    val r = SecureRandom.getInstance(if ( scala.util.Properties.isWin ) ManagedRandom.WinRandom else ManagedRandom.UnixURandom)
    r.nextBytes(new Array[Byte](20)) //Force reseed
    r
  }

  def nextBytes(bytes: Array[Byte]): Unit =
    cachedRand.nextBytes(bytes)
}

object ManagedRandom {
  private[ManagedRandom] val WinRandom = "Windows-PRNG"
  private[ManagedRandom] val UnixURandom = "NativePRNGNonBlocking"
}
