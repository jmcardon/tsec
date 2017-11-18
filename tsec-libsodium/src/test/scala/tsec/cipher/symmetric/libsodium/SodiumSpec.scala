package tsec.cipher.symmetric.libsodium

import org.scalatest.MustMatchers
import org.scalatest.prop.PropertyChecks
import tsec.{ScalaSodium, TestSpec}

trait SodiumSpec extends TestSpec with MustMatchers with PropertyChecks {
  implicit val sodium: ScalaSodium = ScalaSodium.getSodiumUnsafe
}
