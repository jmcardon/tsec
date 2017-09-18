package tsec.cipher.symmetric.instances

import tsec.core.CryptoTag

/**
  * Typeclass for symmetrix key algorithms
  * Note: Keylength is in bits
  *
  * @param algorithm
  * @param keyLength
  * @tparam T
  */
case class SymmetricAlgorithm[T](algorithm: String, keyLength: Int) extends CryptoTag[T]
