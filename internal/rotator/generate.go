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
	runes := []rune(charset)
	if len(runes) > 256 {
		return Result{}, errf("charset must be at most 256 characters")
	}
	max := big.NewInt(int64(len(runes)))
	out := make([]rune, length)
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return Result{}, errf("secure random: %v", err)
		}
		out[i] = runes[n.Int64()]
	}
	return Result{Value: string(out)}, nil
}
