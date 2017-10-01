package tsec.cipher.symmetric.instances

import tsec.core.CryptoTag

/**
  * Typeclass for propagating symmetric key algorithm information
  * Note: Key length is in bits
  *
  * @param algorithm the symmetric cipher representation, as a string
  * @param keyLength key length in bits
  * @tparam T Parametrized cipher type
  */
case class SymmetricAlgorithm[T](algorithm: String, keyLength: Int) extends CryptoTag[T]
