module github.com/zionnode/v2scar-v

require (
	github.com/urfave/cli v1.22.4
	google.golang.org/grpc v1.32.0
	v2ray.com/core v4.19.1+incompatible
)

go 1.15

replace v2ray.com/core => github.com/v2ray/v2ray-core v4.23.1+incompatible
