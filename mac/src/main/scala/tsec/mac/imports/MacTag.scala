package tsec.mac.imports

import tsec.core.CryptoTag

final case class MacTag[T](algorithm: String, keyLength: Int) extends CryptoTag[T]
