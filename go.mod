module github.com/xcrezd/deployer

go 1.12

require (
	github.com/containerd/containerd v1.2.7 // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/gogo/protobuf v1.2.1 // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/sirupsen/logrus v1.4.2
	golang.org/x/net v0.0.0-20190724013045-ca1201d0de80 // indirect
	golang.org/x/sync v0.0.0-20190423024810-112230192c58
	google.golang.org/grpc v1.22.1 // indirect
)

replace github.com/docker/docker v1.13.1 => github.com/moby/moby v0.7.3-0.20190803213401-7449ca395c37
