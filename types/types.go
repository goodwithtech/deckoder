package types

import (
	"archive/tar"
	"errors"
	"time"
)

var (
	InvalidURLPattern = errors.New("invalid url pattern")
)

type FilterFunc func(*tar.Header) (bool, error)
type DockerOption struct {
	AuthURL      string
	UserName     string
	Password     string
	GcpCredPath  string
	AwsAccessKey string
	AwsSecretKey string
	AwsRegion    string
	Insecure     bool
	Debug        bool
	SkipPing     bool
	NonSSL       bool
	Timeout      time.Duration
}
