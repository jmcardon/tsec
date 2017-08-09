package tsec.cipher.instances.mode

import javax.crypto.spec.GCMParameterSpec

import tsec.cipher.instances._

sealed trait GCM
object GCM extends WithModeTag[GCM]("GCM") {
  /*
  in our implementation, we will use the most secure tag size as defined by:
  http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
   */
  val GCMTagLength = 128
  implicit val spec = new ModeKeySpec[GCM] {
    def buildAlgorithmSpec(specBytes: Array[Byte]): JSpec[GCM] =
      tagSpec[GCM](new GCMParameterSpec(GCMTagLength, specBytes))
  }
}
