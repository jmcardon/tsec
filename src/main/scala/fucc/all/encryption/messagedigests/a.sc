
import java.security.MessageDigest

import fucc.all.encryption.messagedigests.javahasher.JHasher
import fucc.all.encryption.messagedigests.core._
import org.apache.commons.codec.binary.Base64
import cats.data._

Base64.encodeBase64String(MessageDigest.getInstance("SHA-256").digest("hihi".getBytes("UTF-8")))
JHasher.SHA1.hashStringToBase64("hi")

def a[T : PureHasher](a: T) = Base64.encodeBase64String(implicitly[PureHasher[T]].bytes(a))

a(JHasher.SHA256.hashCombine("hi"::NonEmptyList.of("hi")))
