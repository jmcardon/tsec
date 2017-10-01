package tsec.cipher.common.mode

import java.security.spec.AlgorithmParameterSpec

import shapeless.tag.@@
import tsec.core.CryptoTag

trait ModeKeySpec[T] extends CryptoTag[T] {
  def buildIvFromBytes(specBytes: Array[Byte]): AlgorithmParameterSpec @@ T
  def genIv: AlgorithmParameterSpec @@ T
}
