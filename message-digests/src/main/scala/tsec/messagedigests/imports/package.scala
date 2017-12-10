package tsec.messagedigests

package object imports {

  def defaultStringPickler: CryptoPickler[String] =
    CryptoPickler.stringPickle[UTF8]

}
