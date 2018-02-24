package tsec.libsodium.cipher.internal

import tsec.keygen.symmetric.SymmetricKeyGenAPI
import tsec.libsodium.cipher.SodiumKey

/** Our symmetric key generator, abstracted out
  * This is not so easy given keyError is useful to CipherError as well, but
  * duplicated classes is a nono
  *
  * @tparam A The algorithm to generate the key for
  */
protected[tsec] trait SodiumKeyGenerator[A] extends SymmetricKeyGenAPI[A, SodiumKey]{

  /** The generator key length
    * @return
    */
  val keyLength: Int

}
