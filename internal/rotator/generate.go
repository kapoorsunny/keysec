package rotator

import (
	"context"
	"crypto/rand"
	"math/big"
)

const defaultCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// generateRotator produces cryptographically random values.
type generateRotator struct {
	spec *Spec
}

func (g *generateRotator) Rotate(_ context.Context, in Input) (Result, error) {
	length := g.spec.Length
	if length <= 0 {
		length = 32
	}
	charset := g.spec.Charset
	if charset == "" {
		charset = defaultCharset
	}
	if len(charset) > 256 {
		return Result{}, errf("charset must be at most 256 characters")
	}
	max := big.NewInt(int64(len(charset)))
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return Result{}, errf("secure random: %v", err)
		}
		b[i] = charset[n.Int64()]
	}
	return Result{Value: string(b)}, nil
}
