package tsec.cipher.instances.mode

sealed trait CFB
object CFB extends WithModeTag[CFB]("CFB") with DefaultModeKeySpec[CFB]
