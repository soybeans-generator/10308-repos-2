# extract items

also script should never remove the first prompt from the user as its either
the original first prompt, or a JSON export from a previous chat both of which
are important - also if the first message an export (output from this script)
then this script should treat it as multiple messages rather than a single
message when deciding what to remove
