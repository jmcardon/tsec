package tsec.asymmetric.core

import tsec.core.CryptoTag

case class AsymmetricAlgorithm[T](algorithm: String) extends CryptoTag[T]
