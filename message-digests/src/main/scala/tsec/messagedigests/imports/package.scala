package tsec.messagedigests

import java.nio.charset.Charset
import java.util.Base64

import shapeless._
import tsec.messagedigests.core._
import tsec.common.ByteUtils.ByteAux

package object imports {

  def defaultStringPickler: CryptoPickler[String] =
    CryptoPickler.stringPickle[UTF8]

}
