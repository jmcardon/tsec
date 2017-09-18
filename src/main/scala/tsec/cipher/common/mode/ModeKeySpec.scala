package tsec.cipher.common.mode

import java.security.spec.AlgorithmParameterSpec

import tsec.core.CryptoTag
import shapeless.tag.@@

trait ModeKeySpec[T] extends CryptoTag[T] {
  def buildIvFromBytes(specBytes: Array[Byte]): AlgorithmParameterSpec @@ T
  def genIv: AlgorithmParameterSpec @@ T
}
