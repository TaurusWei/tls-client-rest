module tls-client-rest

go 1.13

replace github.com/tjfoc/gmsm => ./third_party/github.com/tjfoc/gmsm

replace github.com/tjfoc/gmtls => ./third_party/github.com/tjfoc/gmtls

replace github.com/hyperledger/fabric => ./third_party/github.com/hyperledger/fabric

replace github.com/spf13/viper v1.8.1 => github.com/spf13/viper v1.7.1

replace go.uber.org/zap v1.18.1 => go.uber.org/zap v1.12.0

require (
	github.com/hyperledger/fabric v2.1.1+incompatible
	github.com/pkg/errors v0.9.1
	github.com/prometheus/common v0.6.0
	github.com/thedevsaddam/gojsonq v2.3.0+incompatible
	github.com/tjfoc/gmsm v1.4.1
	github.com/tjfoc/gmtls v1.2.1
)
