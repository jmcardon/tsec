package tsec.cipher.symmetric.bouncy

import org.bouncycastle.crypto.engines.ChaChaEngine
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.util.Pack
import tsec.cipher.symmetric._

trait ChaCha20Poly1305

object ChaCha20Poly1305
    extends AEADAPI[ChaCha20Poly1305, BouncySecretKey]
    with ChaCha20Cipher[ChaCha20Poly1305, ChaChaEngine] {

  def nonceSize: Int = 8

  protected def getCipherImpl: ChaChaEngine = new ChaChaEngine(20)

  protected def poly1305Auth(
      key: KeyParameter,
      aad: AAD,
      in: Array[Byte],
      inSize: Int,
      tagOut: Array[Byte],
      tOutOffset: Int
  ): Unit = {

    val poly1305 = new Poly1305()
    val ctLen    = Pack.longToLittleEndian(inSize & 0xFFFFFFFFL)
    val aadLen   = Pack.longToLittleEndian(aad.length & 0xFFFFFFFFL)
    poly1305.init(key)
    poly1305.update(aad, 0, aad.length)
    poly1305.update(aadLen, 0, ctLen.length)
    poly1305.update(in, 0, inSize)
    poly1305.update(ctLen, 0, ctLen.length)
    poly1305.doFinal(tagOut, tOutOffset)
  }

}
