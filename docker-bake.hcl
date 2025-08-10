group "default" {
  targets = [ "builder-base", "executor-base", "omnipath-debug"]
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

target "omnipath-debug" {
  contexts = {
    builder-base = "target:builder-base"
    executor-base = "target:executor-base"
  }
  args = {
    MODE = "debug"
  }
  dockerfile = "deploy/omnipath/Dockerfile"
  tags = ["unifyair/omnipath-debug:latest"]
  depends_on = ["builder-base", "executor-base"]
} 

target "omnipath-release" {
  contexts = {
    builder-base = "target:builder-base"
    executor-base = "target:executor-base"
  }
  args = {
    MODE = "release"
  }
  dockerfile = "deploy/omnipath/Dockerfile"
  tags = ["unifyair/omnipath-release:latest"]
  depends_on = ["builder-base", "executor-base"]
} 

target "gnbsim" {
  dockerfile = "deploy/gnbsim/Dockerfile"
  args = {
    VERSION = "1.6.3"
    DEBUG_TOOLS = "false"
  }
  tags = ["unifyair/omecproject-gnbsim:1.6.3"]
  depends_on = ["builder-base", "executor-base"]
}