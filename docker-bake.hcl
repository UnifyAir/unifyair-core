group "default" {
  targets = [ "builder-base", "executor-base", "omnipath"]
}


target "builder-base" {
  context = "."
  dockerfile = "deploy/base/Dockerfile.builder"
  tags = ["unifyair/builder-base:latest"]
}

target "executor-base" {
  context = "."
  dockerfile = "deploy/base/Dockerfile.executor"
  tags = ["unifyair/executor-base:latest"]
}

target "omnipath" {
  contexts = {
    builder-base = "target:builder-base"
    executor-base = "target:executor-base"
  }
  dockerfile = "deploy/omnipath/Dockerfile"
  tags = ["unifyair/omnipath"]
  depends_on = ["builder-base", "executor-base"]
} 

target "gnbsim" {
  dockerfile = "deploy/gnbsim/Dockerfile"
  args = {
    VERSION = "1.6.3"
    DEBUG_TOOLS = "false"
  }
  tags = ["omecproject/5gc-gnbsim:rel-1.6.3"]
  depends_on = ["builder-base", "executor-base"]
}