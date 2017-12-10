package tsec.passwordhashers.imports

import tsec.common.ManagedRandom
import tsec.passwordhashers.imports.internal.JBCrypt

private[tsec] object JBCryptUtil extends ManagedRandom {

  /** Generate a salt,
    * but make sure we increment the adder
    * to reseed eventually if necessary
    */
  def genSalt(logRounds: Int): String = {
    val salt = JBCrypt.gensalt(logRounds, cachedRand)
    forceIncrement
    salt
  }

}
