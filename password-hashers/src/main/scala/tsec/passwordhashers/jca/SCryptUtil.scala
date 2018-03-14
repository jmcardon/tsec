package tsec.passwordhashers.jca

import java.security.MessageDigest

import cats.syntax.either._
import com.lambdaworks.codec.Base64
import com.lambdaworks.crypto.{SCrypt => JSCrypt}
import tsec.common.ManagedRandom

/** SCrypt util scala adaption for Will Glozer's (@wg on github) SCryptUtil,
  * improving on SHA1PRNGs, bad security in particular.
  *
  * SCrypt described here: http://www.tarsnap.com/scrypt.html
  *
  * The hashed output is an
  * extended implementation of the Modular Crypt Format that also includes the scrypt
  * algorithm parameters.
  *
  * Format: <code>$s0$PARAMS$SALT$KEY</code>.
  *
  * <dl>
  * <dd>PARAMS</dd><dt>32-bit hex integer containing log2(N) (16 bits), r (8 bits), and p (8 bits)</dt>
  * <dd>SALT</dd><dt>base64-encoded salt</dt>
  * <dd>KEY</dd><dt>base64-encoded derived key</dt>
  * </dl>
  *
  * <code>s0</code> identifies version 0 of the scrypt format, using a 128-bit salt and 256-bit derived key.
  *
  */
object SCryptUtil extends ManagedRandom {

  private val SCryptPrepend = "$s0$"
  private val DerivedKeyLen = 32

  /** Compare the supplied plaintext password to a hashed password.
    *
    * @param   passwd Plaintext password.
    * @param   hashed scrypt hashed password.
    * @return true if passwd matches hashed value.
    */
  def check(passwd: Array[Byte], hashed: String): Boolean = {
    val parts = hashed.split("\\$")
    if (parts.length != 5 || !(parts(1) == "s0")) return false
    val params   = java.lang.Long.parseLong(parts(2), 16)
    val salt     = Base64.decode(parts(3).toCharArray)
    val derived0 = Base64.decode(parts(4).toCharArray)
    val N        = Math.pow(2, params >> 16 & 0xffff).toInt
    val r        = params.toInt >> 8 & 0xff
    val p        = params.toInt & 0xff
    Either.catchNonFatal(JSCrypt.scrypt(passwd, salt, N, r, p, 32)) match {
      case Left(_) => false
      case Right(derived1) =>
        MessageDigest.isEqual(derived0, derived1)
    }
  }

  /** Scala fast log2
    *
    * @param k
    * @return
    */
  private def log2(k: Int) = {
    var n   = k
    var log = 0
    if ((n & 0xffff0000) != 0) {
      n >>>= 16
      log = 16
    }
    if (n >= 256) {
      n >>>= 8
      log += 8
    }
    if (n >= 16) {
      n >>>= 4
      log += 4
    }
    if (n >= 4) {
      n >>>= 2
      log += 2
    }
    log + (n >>> 1)
  }

  /** Hash the supplied plaintext password and generate output in the format described
    * in
    *
    * @param passwd Password.
    * @param N      CPU cost parameter.
    * @param r      Memory cost parameter.
    * @param p      Parallelization parameter.
    * @return The hashed password.
    */
  def scrypt(passwd: Array[Byte], N: Int, r: Int, p: Int): String = {
    val salt = new Array[Byte](16)

    nextBytes(salt)
    val derived = JSCrypt.scrypt(passwd, salt, N, r, p, DerivedKeyLen)
    val params  = java.lang.Long.toString(log2(N) << 16L | r << 8 | p, 16)

    val sb = new java.lang.StringBuilder((salt.length + derived.length) * 2)
    sb.append(SCryptPrepend).append(params).append('$')
    sb.append(Base64.encode(salt)).append('$')
    sb.append(Base64.encode(derived))
    sb.toString
  }

}
