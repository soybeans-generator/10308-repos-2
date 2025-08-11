# z.ai

with the second prompt below, the AI got stuck in a loop, so after five minutes I
made the decision that this model at least is too stupid to be useful

## prompt 1, 2m3s

return the full Go script that:
- Reads an MPEG-DASH MPD XML file path from the CLI: `go run main.go <mpd_file_path>`
- Uses `http://test.test/test.mpd` as the initial MPD URL for resolving all relative BaseURLs
- Outputs a JSON object mapping each `Representation@id` to a list of fully resolved segment URLs

## prompt 2

support SegmentTimeline
