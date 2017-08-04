package fucc.all.encryption.messagedigests

import java.nio.charset.Charset

import fucc.all.encryption.messagedigests.core._
import com.softwaremill.tagging._
import fucc.all.encryption.messagedigests.javahasher.JHasher
import org.apache.commons.codec.binary.Base64

package object implicits {
  implicit val defaultStringEncoder: CryptoPickler[String] = CryptoPickler.stringPickle[UTF8](Charset.forName("UTF-8").taggedWith[UTF8])

  implicit class HasherOps[T](
    val hasher: JHasher[T])
    extends AnyVal {
    def hashStringToBase64(s: String): String =
      Base64.encodeBase64String(hasher.p.bytes(hasher.hash[String](s)(defaultStringEncoder)))
  }
}
