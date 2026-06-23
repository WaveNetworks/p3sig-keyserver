// shamir.go — Shamir secret sharing over GF(256) for split recovery.
//
// `p3sig backup --split M-of-N` cuts the key into N share cards; any M of them
// reconstruct it, M-1 reveal nothing. Each share is useless alone, so they can
// go to different custodians (attorney, safety-deposit box, …) and recovery
// needs a quorum — a natural fit for an estate. No passphrase to remember.
//
// Byte-wise SSS in the AES field (poly 0x11b, generator 0x03), the same scheme
// HashiCorp Vault uses. Pure arithmetic, no dependencies.
package main

import "fmt"

var gfExp [256]byte
var gfLog [256]byte

func init() {
	x := byte(1)
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfLog[x] = byte(i)
		x = gfMulRaw(x, 0x03) // multiply by the generator
	}
	gfExp[255] = 1
}

// gfMulRaw multiplies in GF(2^8) without tables (used to build them).
func gfMulRaw(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[(int(gfLog[a])+int(gfLog[b]))%255]
}

func gfDiv(a, b byte) byte { // b != 0
	if a == 0 {
		return 0
	}
	return gfExp[(int(gfLog[a])-int(gfLog[b])+255)%255]
}

type shareT struct {
	x byte
	m byte // threshold (how many shares are needed)
	y []byte
}

// evalPoly evaluates coeffs[0] + coeffs[1]x + … at x (Horner, GF(256)).
func evalPoly(coeffs []byte, x byte) byte {
	var r byte
	for i := len(coeffs) - 1; i >= 0; i-- {
		r = gfMul(r, x) ^ coeffs[i]
	}
	return r
}

// shamirSplit cuts secret into n shares with threshold m (x = 1..n).
func shamirSplit(secret []byte, m, n int) ([]shareT, error) {
	if m < 2 || m > n || n > 255 {
		return nil, fmt.Errorf("split must be M-of-N with 2 ≤ M ≤ N ≤ 255")
	}
	shares := make([]shareT, n)
	for i := range shares {
		shares[i] = shareT{x: byte(i + 1), m: byte(m), y: make([]byte, len(secret))}
	}
	for bi, b := range secret {
		coeffs := make([]byte, m)
		coeffs[0] = b
		copy(coeffs[1:], mustRandom(m-1)) // a1..a(m-1) random → perfect secrecy below M
		for si := range shares {
			shares[si].y[bi] = evalPoly(coeffs, shares[si].x)
		}
	}
	return shares, nil
}

// shamirCombine reconstructs the secret via Lagrange interpolation at x=0.
func shamirCombine(shares []shareT) ([]byte, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares")
	}
	seen := map[byte]bool{}
	L := len(shares[0].y)
	for _, s := range shares {
		if len(s.y) != L {
			return nil, fmt.Errorf("shares are different lengths — not from the same key")
		}
		if s.x == 0 || seen[s.x] {
			return nil, fmt.Errorf("duplicate or invalid share index")
		}
		seen[s.x] = true
	}
	secret := make([]byte, L)
	for bi := 0; bi < L; bi++ {
		var acc byte
		for i := range shares {
			num, den := byte(1), byte(1)
			for j := range shares {
				if i == j {
					continue
				}
				num = gfMul(num, shares[j].x)             // (0 - x_j) = x_j in GF(2^8)
				den = gfMul(den, shares[i].x^shares[j].x) // (x_i - x_j) = x_i ^ x_j
			}
			acc ^= gfMul(shares[i].y[bi], gfDiv(num, den))
		}
		secret[bi] = acc
	}
	return secret, nil
}
