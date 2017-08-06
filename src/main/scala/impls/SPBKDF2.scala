package impls

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.GeneralSecurityException
import java.lang.System.arraycopy

/**
  * An implementation of the Password-Based Key Derivation Function as specified
  * in RFC 2898.
  *
  * A scala port of Will Glozer's PBKDF2
  *
  */
class SPBKDF2 {

  /**
    * Implementation of PBKDF2 (RFC2898).
    *
    * @param   hmacAlgorithm HMAC algorithm to use.
    * @param   password      Password.
    * @param   salt             Salt.
    * @param   iterationCount             Iteration count.
    * @param   dkLen         Intended length, in octets, of the derived key.
    * @return The derived key.
    */
  def pbkdf2(hmacAlgorithm: String,
             password: Array[Byte],
             salt: Array[Byte],
             iterationCount: Int,
             dkLen: Int): Array[Byte] = {
    val mac = Mac.getInstance(hmacAlgorithm)
    mac.init(new SecretKeySpec(password, hmacAlgorithm))
    val DK = new Array[Byte](dkLen)
    pbkdf2(mac, salt, iterationCount, DK, dkLen)
    DK
  }

  /**
    * Implementation of PBKDF2 (RFC2898).
    *
    * @param   mac   Pre-initialized { @link Mac} instance to use.
    * @param   S     Salt.
    * @param   c     Iteration count.
    * @param   DK    Byte array that derived key will be placed in.
    * @param   dkLen Intended length, in octets, of the derived key.
    */
  def pbkdf2(mac: Mac, S: Array[Byte], c: Int, DK: Array[Byte], dkLen: Int) {
    val hLen = mac.getMacLength
    if (dkLen > (Math.pow(2, 32) - 1) * hLen)
      throw new GeneralSecurityException("Requested key length too long")
    val U = new Array[Byte](hLen)
    val T: Array[Byte] = new Array[Byte](hLen)
    val block1 = new Array[Byte](S.length + 4)
    val l = Math.ceil(dkLen.toDouble / hLen).toInt
    val r = dkLen - (l - 1) * hLen
    arraycopy(S, 0, block1, 0, S.length)
    var i = 1
    while (i <= l) {
      {
        block1(S.length + 0) = (i >> 24 & 0xff).toByte
        block1(S.length + 1) = (i >> 16 & 0xff).toByte
        block1(S.length + 2) = (i >> 8 & 0xff).toByte
        block1(S.length + 3) = (i >> 0 & 0xff).toByte
        mac.update(block1)
        mac.doFinal(U, 0)
        arraycopy(U, 0, T, 0, hLen)
        var j = 1
        while (j < c) {
          {
            mac.update(U)
            mac.doFinal(U, 0)
            var k = 0
            while (k < hLen) {
              {
                T(k) = (T(k) ^ U(k)).toByte
              }
              {
                k += 1
                k - 1
              }
            }
          }
          {
            j += 1
            j - 1
          }
        }
        arraycopy(T,
                  0,
                  DK,
                  (i - 1) * hLen,
                  if (i == l) r
                  else hLen)
      }
      {
        i += 1
        i - 1
      }
    }
  }

}
