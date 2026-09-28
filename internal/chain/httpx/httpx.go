// Package httpx is the bounded HTTP client the chain mechanisms use for
// JSON-RPC and REST queries: no redirects, a size ceiling and a timeout.
package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

const maxBody = 4 << 20

var Client = &http.Client{
	Timeout:       30 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func do(ctx context.Context, method, url string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := Client.Do(req)
	if err != nil {
		return errors.New("chain endpoint unavailable")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(b) > maxBody {
		return errors.New("chain response too large or truncated")
	}
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("chain endpoint returned HTTP %d", resp.StatusCode)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	return d.Decode(out)
}

// ErrNotFound is a REST 404, such as an unknown account or transaction.
var ErrNotFound = errors.New("not found")

func GetJSON(ctx context.Context, url string, out any) error {
	return do(ctx, http.MethodGet, url, nil, out)
}

func PostJSON(ctx context.Context, url string, in, out any) error {
	return do(ctx, http.MethodPost, url, in, out)
}

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

var ids atomic.Int64

// Call performs a JSON-RPC 2.0 request.
func Call(ctx context.Context, url, method string, params, result any) error {
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  *RPCError       `json:"error"`
	}
	req := map[string]any{"jsonrpc": "2.0", "id": ids.Add(1), "method": method}
	if params != nil {
		req["params"] = params
	}
	if err := PostJSON(ctx, url, req, &resp); err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	if len(resp.Result) == 0 {
		return errors.New("rpc response has no result")
	}
	d := json.NewDecoder(bytes.NewReader(resp.Result))
	d.UseNumber()
	return d.Decode(result)
}
