package tsec.cipher.symmetric.mode

import javax.crypto.spec.GCMParameterSpec
import java.security.SecureRandom
import java.util.concurrent.atomic.LongAdder

import tsec.common.ManagedRandom

trait CipherModes {

  /*
  Modes of operation
   */
  sealed trait CBC

  /** our cbc mode takes 16 byte IVs
    * https://crypto.stackexchange.com/questions/2594/initialization-vector-length-insufficient-in-aes
    */
  object CBC extends DefaultModeKeySpec[CBC]("CBC", 16)

  sealed trait CFB
  object CFB extends DefaultModeKeySpec[CFB]("CFB", 32)

  sealed trait CFBx
  object CFBx extends DefaultModeKeySpec[CFBx]("CFBx", 32)

  sealed trait CTR
  object CTR extends DefaultModeKeySpec[CTR]("CTR", 16)

  trait ECB
  object ECB extends DefaultModeKeySpec[ECB]("ECB", 0)

  sealed trait GCM
  object GCM {

    /** In our implementation, we will use the most secure tag size as defined
      * by: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
      *  Iv length of 96 bits is recommended as per the spec on page 8
      */
    val GCMTagLength        = 128
    val GCMIvOptionalLength = 12
    implicit lazy val spec = new AEADMode[GCM] with ManagedRandom { self =>

      val ivLength: Int = GCMIvOptionalLength

      def algorithm: String = "GCM"
      def buildIvFromBytes(specBytes: Array[Byte]): ParameterSpec[GCM] =
        ParameterSpec.fromSpec[GCM](new GCMParameterSpec(GCMTagLength, specBytes))(self)

      def genIv: ParameterSpec[GCM] = {
        val newBytes = new Array[Byte](12)
        nextBytes(newBytes)
        ParameterSpec.fromSpec[GCM](new GCMParameterSpec(GCMTagLength, newBytes))(self)
      }
    }
  }

  sealed trait NoMode
  object NoMode extends DefaultModeKeySpec[NoMode]("NONE", 0)

  sealed trait OFB
  object OFB extends DefaultModeKeySpec[OFB]("OFB", 16)

  sealed trait OFBx
  object OFBx extends DefaultModeKeySpec[OFBx]("OFBx", 16)

  sealed trait PCBC
  object PCBC extends DefaultModeKeySpec[PCBC]("PCBC", 16)

}
