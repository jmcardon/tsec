package tsec.symmetric.core

import tsec.core.CryptoTag

case class SymmetricAlgorithm[T](algorithm: String, keylength: Int) extends CryptoTag[T]
