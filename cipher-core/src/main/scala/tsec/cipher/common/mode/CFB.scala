package tsec.cipher.common.mode

sealed trait CFB
object CFB extends DefaultModeKeySpec[CFB]("CFB", 32)
