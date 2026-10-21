// helpers.go
package main

import "net/url"

func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}
// helpers.go
