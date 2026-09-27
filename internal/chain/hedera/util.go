package hedera

import "encoding/base64"

func encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
