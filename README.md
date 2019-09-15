# deckoder
Check files in docker image

fork from [aquasecurity/fanal](https://github.com/aquasecurity/fanal)

## Feature

- Fetch target image data if there is no image in local
- Check target condition files

## Examples

```go
ctx := context.Background()
var files extractor.FileMap

// Only check file path
filterFunc := func(h *tar.Header) (bool, error) {
    filePath := filepath.Clean(h.Name)
    fileName := filepath.Base(filePath)
    return StringInSlice(filePath, filenames) || StringInSlice(fileName, filenames), nil
}

files, err = analyzer.Analyze(ctx, imageName, filterFunc, dockerOption)
if err != nil {
	return nil, fmt.Errorf("failed to analyze image: %w", err)
}

// files => map[filename string]FileData{
//              Body     []byte      : file bytes
//              FileMode os.FileMode : file's mode
// }

```


## Notes
When using `latest` tag, that image will be cached. After `latest` tag is updated, you need to clear cache.
