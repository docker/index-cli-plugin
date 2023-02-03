package sbom

import (
	"context"
	"time"

	"github.com/atomist-skills/go-skill"

	"github.com/docker/cli/cli/command"
	"github.com/docker/docker/api/types"
)

var imageCache map[string]types.ImageSummary

const maxIndexWorkers = 2

func init() {
	imageCache = make(map[string]types.ImageSummary)
}

func WatchImages(cli command.Cli) error {
	indexJobs := make(chan types.ImageSummary)
	for w := 1; w <= maxIndexWorkers; w++ {
		go indexImageWorker(cli, indexJobs)
	}

	for range time.Tick(time.Second * 5) { //nolint:staticcheck
		images, err := cli.Client().ImageList(context.Background(), types.ImageListOptions{
			All: false,
		})
		if err != nil {
			return err
		}

		for _, img := range images {
			if _, ok := imageCache[img.ID]; !ok {
				skill.Log.Infof("Scheduling image %s for indexing", img.ID)
				imageCache[img.ID] = img
				indexJobs <- img
			}
		}
	}
	return nil
}

func indexImageWorker(cli command.Cli, indexJobs <-chan types.ImageSummary) {
	for img := range indexJobs {
		_, err := IndexImage(img.ID, IndexOptions{Cli: cli})
		if err != nil {
			skill.Log.Warnf("Failed to index image %s", img.ID)
			delete(imageCache, img.ID)
		}
	}
}
