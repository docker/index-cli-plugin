**Note:** This repository is not an officially supported Docker project.

# `docker index` Docker CLI tool

Docker CLI tool to create image SBOMs as well as analyze packages for known vulnerabilities 
using the Atomist data plane.

## Installation

You can install manually by following these steps:

* Download the binary from the [release page](https://github.com/docker/index-cli-plugin/releases/latest)
* Unzip the archive

## Usage

### `docker-index sbom`

To create an SBOM for a local or remote image, run the following command:

```shell
$ docker-index sbom --image <IMAGE> 
```

* `--image <IMAGE>` can either be a local image id or fully qualified image name from a remote registry
* `--oci-dir <DIR>` can point to a local image in OCI directory format
* `--output <OUTPUT FILE>` allows to store the generated SBOM in a local file
* `--include-cves` will include all detected CVEs in generated output
### `scanner.sh`

To scan all of local images , use the following command:
```shell
./checker.sh
```

### `docker-index cve`

To detect base images for local or remote images, use the following command:

```shell
$ docker-index cve --image <IMAGE> CVE_ID 
```

* `--image <IMAGE>` can either be a local image id or fully qualified image name from a remote registry
* `--oci-dir <DIR>` can point to a local image in OCI directory format
* `--remediate` include suggested remediation in the output
* `CVE_ID` can be any known CVE id
