package tsec.mac.imports

import tsec.common.CryptoTag

final case class MacTag[T](algorithm: String, keyLength: Int) extends CryptoTag[T]
