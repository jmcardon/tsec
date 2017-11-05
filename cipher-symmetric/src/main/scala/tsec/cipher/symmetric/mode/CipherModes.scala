package tsec.cipher.symmetric.mode

import javax.crypto.spec.GCMParameterSpec
import java.security.SecureRandom
import java.util.concurrent.atomic.LongAdder

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
    implicit lazy val spec = new AEADMode[GCM] { self =>

      val ivLength: Int = GCMIvOptionalLength

      /** Cache our random, and seed it properly as per
        * https://tersesystems.com/2015/12/17/the-right-way-to-use-securerandom/
        */
      private var cachedRand: SecureRandom = {
        val r = new SecureRandom()
        r.nextBytes(new Array[Byte](20))
        r
      }

      /** We will keep a reference to how many times our random is utilized
        * After a sensible Integer.MaxValue/2 times, we should reseed
        */
      private val adder: LongAdder = new LongAdder
      private val MaxBeforeReseed  = (Integer.MAX_VALUE / 2).toLong

      private def reSeed(): Unit = {
        adder.reset()
        val tmpRand = new SecureRandom()
        tmpRand.nextBytes(new Array[Byte](20))
        cachedRand = tmpRand
      }

      def algorithm: String = "GCM"
      def buildIvFromBytes(specBytes: Array[Byte]): ParameterSpec[GCM] =
        ParameterSpec.fromSpec[GCM](new GCMParameterSpec(GCMTagLength, specBytes))(self)

      def genIv: ParameterSpec[GCM] = {
        adder.increment()
        if (adder.sum() == MaxBeforeReseed)
          reSeed()

        val newBytes = new Array[Byte](12)
        cachedRand.nextBytes(newBytes)
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
