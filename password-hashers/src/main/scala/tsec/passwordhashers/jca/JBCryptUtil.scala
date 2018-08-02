package tsec.passwordhashers.jca

import tsec.common.ManagedRandom
import tsec.passwordhashers.jca.internal.JBCrypt

private[tsec] object JBCryptUtil extends ManagedRandom {

  /** Generate a salt,
    * but make sure we increment the adder
    * to reseed eventually if necessary
    */
  def genSalt(logRounds: Int): String =
    JBCrypt.gensalt(logRounds, cachedRand)

}
