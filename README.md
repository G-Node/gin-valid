[![Build](https://github.com/g-node/gin-valid/workflows/run-build/badge.svg?branch=master)](https://github.com/G-Node/gin-valid/actions)
[![Coverage Status](https://coveralls.io/repos/github/G-Node/gin-valid/badge.svg?branch=master)](https://coveralls.io/github/G-Node/gin-valid?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/g-node/gin-valid)](https://goreportcard.com/report/github.com/g-node/gin-valid)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/g-node/gin-valid)](https://pkg.go.dev/github.com/G-Node/gin-valid)
[![Docker Automated build](https://img.shields.io/docker/automated/gnode/gin-valid.svg)](https://hub.docker.com/r/gnode/gin-valid)

# gin-valid

gin-valid is the G-Node Infrastructure data validation service. It is a microservice server written in go that is meant to be run dependent on a [https://github.com/G-Node/gogs](GIN repository server).

Repositories on a GIN server can trigger validation of data files via this service. The currently supported validators are listed below.
- The [BIDS](https://bids.neuroimaging.io) fMRI data format.
- The [NIX](https://g-node.org/nix) (Neuroscience Information Exchange) format.
- The [odML](https://g-node.org/odml) (open metadata markup language) format.

## Contributing

For instructions on how to create and add custom validators, please check the [adding validators](docs/adding-validators.md) contribution guide.
