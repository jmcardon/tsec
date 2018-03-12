package tsec.mac.core

import tsec.common.CryptoTag

protected[tsec] trait JCAMacTag[T] extends CryptoTag[T]

object JCAMacTag {
  @inline def apply[T](implicit M: JCAMacTag[T]): JCAMacTag[T] = M
}
