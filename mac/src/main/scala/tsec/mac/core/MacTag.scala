package tsec.mac.core

import tsec.common.CryptoTag

protected[tsec] trait MacTag[T] extends CryptoTag[T]

object MacTag {
  @inline def apply[T](implicit M: MacTag[T]): MacTag[T] = M
}
