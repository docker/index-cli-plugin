# `docker index` Docker CLI plugin

Docker CLI plugin to create image SBOMs as well as analyze packages for known vulnerabilities 
using the Atomist data plane.

## Installation

To install, run the following command in your terminal:

```shell
$ curl -sSfL https://raw.githubusercontent.com/docker/index-cli-plugin/main/install.sh | sh -s --
```

Alternatively, you can install manually by following these steps:

* Download the plugin binary from the [release page](https://github.com/docker/index-cli-plugin/releases/latest)
* Unzip the archive
* Copy/move the binary into `$HOME/.docker/cli-plugins`

## Usage

### `docker index sbom`

To detect base images for local or remote images, use the following command:

```shell
$ docker index sbom --image <IMAGE> 
```

`<IMAGE>` can either be a local image id or fully qualified image name from a remote registry.

`--output <OUTPUT FILE>` allows to store the generated SBOM in a local file.
