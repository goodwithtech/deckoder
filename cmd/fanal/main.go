package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/goodwithtech/deckoder/cache"
	"github.com/goodwithtech/deckoder/utils"
	"golang.org/x/xerrors"

	"github.com/goodwithtech/deckoder/analyzer"
	"github.com/goodwithtech/deckoder/extractor"
	"github.com/goodwithtech/deckoder/extractor/docker"
	"github.com/goodwithtech/deckoder/types"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("%+v", err)
	}
}

func run() (err error) {
	ctx := context.Background()
	tarPath := flag.String("f", "-", "layer.tar path")
	clearCache := flag.Bool("clear", false, "clear cache")
	flag.Parse()

	c, err := cache.NewFSCache(utils.CacheDir())
	if err != nil {
		return err
	}

	if *clearCache {
		if err = c.Clear(); err != nil {
			return xerrors.Errorf("%w", err)
		}
		return nil
	}

	args := flag.Args()

	opt := types.DockerOption{
		Timeout:  600 * time.Second,
		SkipPing: true,
	}

	var ext extractor.Extractor
	var cleanup func()
	if len(args) > 0 {
		ext, cleanup, err = docker.NewDockerExtractor(ctx, args[0], opt)
		if err != nil {
			return err
		}
	} else {
		ext, cleanup, err = docker.NewDockerArchiveExtractor(ctx, *tarPath, opt)
		if err != nil {
			return err
		}
	}
	defer cleanup()

	ac := analyzer.New(ext, c)
	imageInfo, err := ac.Analyze(ctx)
	if err != nil {
		return err
	}

	a := analyzer.NewApplier(c)
	mergedLayer, err := a.ApplyLayers(imageInfo.ID, imageInfo.LayerIDs)
	if err != nil {
		return err
	}

	fmt.Printf("%+v\n", mergedLayer.OS)
	fmt.Printf("via image Packages: %d\n", len(mergedLayer.Packages))
	for _, app := range mergedLayer.Applications {
		fmt.Printf("%s (%s): %d\n", app.Type, app.FilePath, len(app.Libraries))
	}
	return nil
}

func openStream(path string) (*os.File, error) {
	if path == "-" {
		if terminal.IsTerminal(0) {
			flag.Usage()
			os.Exit(64)
		} else {
			return os.Stdin, nil
		}
	}
	return os.Open(path)
}
