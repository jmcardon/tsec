package tsec.build

object GenSodiumPlugin extends sbt.AutoPlugin {
  import sbt._

  override def requires = empty
  override def trigger = allRequirements

  object autoImport {
    lazy val gensodium = taskKey[Unit]("Generate ScalaSodium0.scala")
  }
  import autoImport._

  override def buildSettings = Seq(
    /* See plugins.sbt for why this is dynamically loaded */
    gensodium := {
      getClass.getClassLoader
        .loadClass("tsec.build.GenSodium")
        .getMethod("main", classOf[Array[String]])
        .invoke(null, Array.empty[String])
    }
  )

}
