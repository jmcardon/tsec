package tsec.cipher.instances.mode

sealed trait CFB
object CFB extends DefaultModeKeySpec[CFB]("CFB")
