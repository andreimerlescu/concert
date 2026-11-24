//go:build !wordpress && !enterprise

package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

func hasWordPressEdition() bool { return false }

type fcgiTransport struct{}
type pageMicroCache struct{}

func isFastCGITarget(u *url.URL) bool {
	if u == nil {
		return false
	}
	s := strings.ToLower(u.Scheme)
	return s == "fcgi" || s == "fcgi+unix"
}

func validateFastCGITarget(u *url.URL) error {
	return fmt.Errorf("FastCGI upstream %q is provided by wpconcert (or econcert); build with: go build -tags wordpress ./cmd/wpconcert", u.Redacted())
}

func newFCGITransportWithStats(config, *counters) (*fcgiTransport, error) {
	return nil, fmt.Errorf("FastCGI upstream requires wpconcert (or econcert); build with: go build -tags wordpress ./cmd/wpconcert")
}

func closeFCGITransport(*fcgiTransport) {}

func dialCheckFCGI(context.Context, *fcgiTransport, *url.URL) error {
	return fmt.Errorf("FastCGI not enabled in this build")
}

func roundTripFCGI(*fcgiTransport, *http.Request, *url.URL) (*http.Response, error) {
	return nil, fmt.Errorf("FastCGI not enabled in this build")
}

func withFastCGIClientIP(req *http.Request, _ string) *http.Request       { return req }
func withFastCGIBodyAbort(req *http.Request, _ func() bool) *http.Request { return req }

func maybeGzipFastCGI(*http.Request, *http.Response) {}

func buildMicroCache(config, *counters) *pageMicroCache { return nil }
func sameMicroCache(config, config) bool                { return true }
func (g *generation) microCacheMiddleware(c *gin.Context) {
	c.Next()
}
func writeWordPressMetrics(*strings.Builder, *generation, *counters) {}

func wordpressSettingDefs() []settingDef { return nil }

func movedWordPressFlags() map[string]string {
	return map[string]string{
		"fcgi-index":         "wpconcert",
		"fcgi-deny-paths":    "wpconcert",
		"micro-cache-ttl":    "wpconcert",
		"micro-cache-max-mb": "wpconcert",
		"wp-preset":          "wpconcert",
	}
}

func wordpressSubcommand(name string) func([]string, io.Writer) error {
	switch name {
	case "doctor", "init":
		return func([]string, io.Writer) error {
			return fmt.Errorf("subcommand %q is provided by wpconcert (build with: go build -tags wordpress ./cmd/wpconcert)", name)
		}
	}
	return nil
}

func applyWordPressPreset(*config) error {
	return fmt.Errorf("preset wordpress requires wpconcert (or econcert); build with: go build -tags wordpress ./cmd/wpconcert")
}
