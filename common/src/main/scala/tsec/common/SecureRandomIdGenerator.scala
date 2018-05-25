package tsec.common

import cats.effect.Sync
import org.apache.commons.codec.binary.Hex

case class SecureRandomIdGenerator(sizeInBytes: Int = 32) extends ManagedRandom {
  def generate: SecureRandomId = {
    val byteArray = new Array[Byte](sizeInBytes)
    nextBytes(byteArray)
    new String(Hex.encodeHex(byteArray)).asInstanceOf[SecureRandomId]
  }

  def generateF[F[_]](implicit F: Sync[F]): F[SecureRandomId] = F.delay(generate)
}

//Todo: Possible use case for refined?
object SecureRandomId {
  lazy val Strong: SecureRandomIdGenerator      = SecureRandomIdGenerator(32)
  lazy val Interactive: SecureRandomIdGenerator = SecureRandomIdGenerator(16)

  def apply(s: String): SecureRandomId  = s.asInstanceOf[SecureRandomId]
  def coerce(s: String): SecureRandomId = s.asInstanceOf[SecureRandomId]

}
