package tsec.common

import cats.evidence.Is
import org.apache.commons.codec.binary.Hex

case class SecureRandomIdGenerator(sizeInBytes: Int = 32) extends ManagedRandom {
  def generate: SecureRandomId = {
    val byteArray = new Array[Byte](sizeInBytes)
    nextBytes(byteArray)
    SecureRandomId$$.is.flip.coerce(Hex.encodeHexString(byteArray))
  }
}

object SecureRandomId extends SecureRandomIdGenerator(32) {
  @inline def is: Is[SecureRandomId, String] = SecureRandomId$$.is
  def coerce(s: String): SecureRandomId      = is.flip.coerce(s)
}
