package tsec.cipher.common.mode

import tsec.cipher.common.JSpec
import tsec.core.CryptoTag

trait ModeKeySpec[T] extends CryptoTag[T] {
  def buildIvFromBytes(specBytes: Array[Byte]): JSpec[T]
  def genIv: JSpec[T]
}
