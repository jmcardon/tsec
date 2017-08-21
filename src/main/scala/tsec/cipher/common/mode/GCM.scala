package tsec.cipher.common.mode

import java.security.SecureRandom
import java.util.concurrent.atomic.LongAdder
import javax.crypto.spec.GCMParameterSpec

import com.sun.beans.editors.ByteEditor
import tsec.cipher.common._

sealed trait GCM
object GCM {
  /*
  in our implementation, we will use the most secure tag size as defined by:
  http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

  Iv length of 96 bits is recommended as per the spec on page 8
   */
  val GCMTagLength = 128
  val GCMIvOptionalLength = 12
  implicit lazy val spec = new ModeKeySpec[GCM] {
    /**
     * Cache our random, and seed it properly as per
     * https://tersesystems.com/2015/12/17/the-right-way-to-use-securerandom/
     *
     */
    private val cachedRand: SecureRandom = {
      val r = new SecureRandom()
      r.nextBytes(new Array[Byte](20))
      r
    }

    /**
     * We will keep a reference to how many times our random is utilized
     * After a sensible Integer.MaxValue/2 times, we should reseed
     *
     */
    private val adder: LongAdder = new LongAdder
    private val MaxBeforeReseed = (Integer.MAX_VALUE / 2).toLong

    private def reSeed(): Unit =  {
      adder.reset()
      cachedRand.nextBytes(new Array[Byte](20))
    }

    def algorithm: String = "GCM"
    def buildIvFromBytes(specBytes: Array[Byte]): JSpec[GCM] =
      tagSpec[GCM](new GCMParameterSpec(GCMTagLength, specBytes))

    def genIv: JSpec[GCM] = {
      adder.increment()
      if(adder.sum() >= MaxBeforeReseed)
        reSeed()

      val newBytes = new Array[Byte](12)
      cachedRand.nextBytes(newBytes)
      tagSpec[GCM](new GCMParameterSpec(GCMTagLength, newBytes))
    }
  }
}
