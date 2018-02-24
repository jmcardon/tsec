package tsec.common

import org.apache.commons.codec.binary.Hex

case class SecureRandomIdGenerator(sizeInBytes: Int = 32) extends ManagedRandom {
  def generate: SecureRandomId = {
    val byteArray = new Array[Byte](sizeInBytes)
    nextBytes(byteArray)
    new String(Hex.encodeHex(byteArray)).asInstanceOf[SecureRandomId]
  }
}

object SecureRandomId extends SecureRandomIdGenerator(32) {
  def apply(s: String): SecureRandomId  = s.asInstanceOf[SecureRandomId]
  def coerce(s: String): SecureRandomId = s.asInstanceOf[SecureRandomId]
}
