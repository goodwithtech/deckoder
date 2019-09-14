package analyzer

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/goodwithtech/deckoder/extractor"
	"github.com/goodwithtech/deckoder/extractor/docker"
	"github.com/goodwithtech/deckoder/types"
)

func Analyze(ctx context.Context, imageName string, filterFunc types.FilterFunc, opts ...types.DockerOption) (fileMap extractor.FileMap, err error) {
	// default docker option
	opt := types.DockerOption{
		Timeout: 600 * time.Second,
	}
	if len(opts) > 0 {
		opt = opts[0]
	}

	e := docker.NewDockerExtractor(opt)
	r, err := e.SaveLocalImage(ctx, imageName)
	if err != nil {
		// when no docker daemon is installed or no image exists in the local machine
		fileMap, err = e.Extract(ctx, imageName, filterFunc)
		if err != nil {
			return nil, fmt.Errorf("failed to extract files: %w", err)
		}
		return fileMap, nil
	}

	fileMap, err = e.ExtractFromFile(ctx, r, filterFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to extract files from saved tar: %w", err)
	}
	return fileMap, nil
}

func AnalyzeFromFile(ctx context.Context, r io.ReadCloser, filterFunc types.FilterFunc) (fileMap extractor.FileMap, err error) {
	e := docker.NewDockerExtractor(types.DockerOption{})
	fileMap, err = e.ExtractFromFile(ctx, r, filterFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to extract files from saved tar: %w", err)
	}
	return fileMap, nil
}
