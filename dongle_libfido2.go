//go:build libfido2 && cgo

package main

// dongle_libfido2.go — the libfido2 backend of the Dongle interface (task #2630).
//
// Build: CC=gcc go build -tags libfido2 (on the builder boxes ~/.local/bin/cc is
// the Claude Code launcher and shadows the C compiler).
//
// The prototypes below are declared here rather than taken from <fido.h>, so the
// build needs only the runtime library (libfido2-1 / brew libfido2), not the -dev
// package. They are the stable libfido2 1.x ABI; the opaque struct tags match
// fido/types.h.

/*
#cgo linux LDFLAGS: -l:libfido2.so.1
#cgo !linux LDFLAGS: -lfido2
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct fido_dev fido_dev_t;
typedef struct fido_dev_info fido_dev_info_t;
typedef struct fido_cred fido_cred_t;
typedef struct fido_assert fido_assert_t;
typedef struct fido_credman_rk fido_credman_rk_t;
typedef enum { FIDO_OPT_OMIT, FIDO_OPT_FALSE, FIDO_OPT_TRUE } fido_opt_t;

void fido_init(int);
const char *fido_strerr(int);

fido_dev_info_t *fido_dev_info_new(size_t);
int fido_dev_info_manifest(fido_dev_info_t *, size_t, size_t *);
const fido_dev_info_t *fido_dev_info_ptr(const fido_dev_info_t *, size_t);
const char *fido_dev_info_path(const fido_dev_info_t *);
const char *fido_dev_info_product_string(const fido_dev_info_t *);
void fido_dev_info_free(fido_dev_info_t **, size_t);

fido_dev_t *fido_dev_new(void);
int fido_dev_open(fido_dev_t *, const char *);
int fido_dev_close(fido_dev_t *);
void fido_dev_free(fido_dev_t **);
bool fido_dev_has_pin(const fido_dev_t *);
int fido_dev_set_pin(fido_dev_t *, const char *, const char *);

fido_cred_t *fido_cred_new(void);
void fido_cred_free(fido_cred_t **);
int fido_cred_set_type(fido_cred_t *, int);
int fido_cred_set_rp(fido_cred_t *, const char *, const char *);
int fido_cred_set_user(fido_cred_t *, const unsigned char *, size_t, const char *, const char *, const char *);
int fido_cred_set_clientdata_hash(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_set_rk(fido_cred_t *, fido_opt_t);
int fido_cred_set_prot(fido_cred_t *, int);
int fido_dev_make_cred(fido_dev_t *, fido_cred_t *, const char *);
int fido_cred_type(const fido_cred_t *);
const unsigned char *fido_cred_pubkey_ptr(const fido_cred_t *);
size_t fido_cred_pubkey_len(const fido_cred_t *);
const unsigned char *fido_cred_id_ptr(const fido_cred_t *);
size_t fido_cred_id_len(const fido_cred_t *);

fido_credman_rk_t *fido_credman_rk_new(void);
void fido_credman_rk_free(fido_credman_rk_t **);
int fido_credman_get_dev_rk(fido_dev_t *, const char *, fido_credman_rk_t *, const char *);
size_t fido_credman_rk_count(const fido_credman_rk_t *);
const fido_cred_t *fido_credman_rk(const fido_credman_rk_t *, size_t);

fido_assert_t *fido_assert_new(void);
void fido_assert_free(fido_assert_t **);
int fido_assert_set_rp(fido_assert_t *, const char *);
int fido_assert_set_clientdata_hash(fido_assert_t *, const unsigned char *, size_t);
int fido_assert_allow_cred(fido_assert_t *, const unsigned char *, size_t);
int fido_assert_set_up(fido_assert_t *, fido_opt_t);
int fido_dev_get_assert(fido_dev_t *, fido_assert_t *, const char *);
size_t fido_assert_count(const fido_assert_t *);
uint8_t fido_assert_flags(const fido_assert_t *, size_t);
uint32_t fido_assert_sigcount(const fido_assert_t *, size_t);
const unsigned char *fido_assert_sig_ptr(const fido_assert_t *, size_t);
size_t fido_assert_sig_len(const fido_assert_t *, size_t);
*/
import "C"

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"
)

const (
	fidoOK                 = 0
	fidoErrPINRequired     = 0x36
	fidoErrPINInvalid      = 0x31
	fidoErrNoCredentials   = 0x2e
	coseES256              = -7
	fidoCredProtUVRequired = 0x03
)

func init() {
	C.fido_init(0)
	openDongles = libfido2Open
}

func fidoErr(op string, r C.int) error {
	switch r {
	case fidoOK:
		return nil
	case fidoErrPINRequired:
		return ErrPINRequired
	case fidoErrPINInvalid:
		return errors.New("dongle: wrong PIN (it locks after repeated wrong tries)")
	}
	return fmt.Errorf("dongle: %s: %s", op, C.GoString(C.fido_strerr(r)))
}

func libfido2Open() ([]Dongle, error) {
	const max = 16
	di := C.fido_dev_info_new(max)
	if di == nil {
		return nil, errors.New("dongle: out of memory")
	}
	defer C.fido_dev_info_free(&di, max)
	var n C.size_t
	if err := fidoErr("list", C.fido_dev_info_manifest(di, max, &n)); err != nil {
		return nil, err
	}
	var out []Dongle
	for i := C.size_t(0); i < n; i++ {
		p := C.fido_dev_info_ptr(di, i)
		path := C.GoString(C.fido_dev_info_path(p))
		out = append(out, &fidoDongle{info: DongleInfo{
			Path:    path,
			Product: strings.TrimSpace(C.GoString(C.fido_dev_info_product_string(p))),
			Serial:  usbSerial(path),
		}})
	}
	if len(out) == 0 {
		// libfido2 skips a hidraw node it cannot open, so EACCES looks like "no
		// dongle". Surface it so hidrawHint can print the udev fix.
		if err := unreadableHidraw(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// unreadableHidraw reports a /dev/hidraw* that exists but is not ours to open.
func unreadableHidraw() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	nodes, _ := filepath.Glob("/dev/hidraw*")
	for _, n := range nodes {
		f, err := os.Open(n)
		if err == nil {
			f.Close()
			continue
		}
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("no FIDO2 dongle readable: %w", err)
		}
	}
	return nil
}

// usbSerial reads the USB iSerial of a Linux hidraw node from sysfs
// (/sys/class/hidraw/hidrawN/device is the HID device; two levels up is the USB
// device). Elsewhere, or when absent, it is "" and the label is the product name.
func usbSerial(path string) string {
	if runtime.GOOS != "linux" || !strings.HasPrefix(path, "/dev/hidraw") {
		return ""
	}
	b, err := os.ReadFile(filepath.Join("/sys/class/hidraw", filepath.Base(path), "device/../../serial"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

type fidoDongle struct{ info DongleInfo }

func (d *fidoDongle) Info() DongleInfo { return d.info }

// with opens the device for one operation and always closes it.
func (d *fidoDongle) with(fn func(dev *C.fido_dev_t) error) error {
	dev := C.fido_dev_new()
	if dev == nil {
		return errors.New("dongle: out of memory")
	}
	defer C.fido_dev_free(&dev)
	cp := C.CString(d.info.Path)
	defer C.free(unsafe.Pointer(cp))
	if r := C.fido_dev_open(dev, cp); r != fidoOK {
		if _, err := os.Open(d.info.Path); errors.Is(err, os.ErrPermission) {
			return err
		}
		return fidoErr("open "+d.info.Path, r)
	}
	defer C.fido_dev_close(dev)
	return fn(dev)
}

func cstrOrNil(s string) (*C.char, func()) {
	if s == "" {
		return nil, func() {}
	}
	c := C.CString(s)
	return c, func() { C.free(unsafe.Pointer(c)) }
}

func cbytes(b []byte) *C.uchar { return (*C.uchar)(unsafe.Pointer(&b[0])) }

func (d *fidoDongle) HasPIN() (has bool, err error) {
	err = d.with(func(dev *C.fido_dev_t) error {
		has = bool(C.fido_dev_has_pin(dev))
		return nil
	})
	return
}

func (d *fidoDongle) SetPIN(pin string) error {
	return d.with(func(dev *C.fido_dev_t) error {
		p := C.CString(pin)
		defer C.free(unsafe.Pointer(p))
		return fidoErr("set PIN", C.fido_dev_set_pin(dev, p, nil))
	})
}

// credFrom copies an ES256 credential out of libfido2 (pubkey is raw x||y).
func credFrom(app string, c *C.fido_cred_t) (DongleCred, error) {
	if C.fido_cred_type(c) != coseES256 {
		return DongleCred{}, errors.New("dongle: credential is not ES256")
	}
	pk := C.GoBytes(unsafe.Pointer(C.fido_cred_pubkey_ptr(c)), C.int(C.fido_cred_pubkey_len(c)))
	if len(pk) != 64 {
		return DongleCred{}, fmt.Errorf("dongle: unexpected ES256 public key length %d", len(pk))
	}
	id := C.GoBytes(unsafe.Pointer(C.fido_cred_id_ptr(c)), C.int(C.fido_cred_id_len(c)))
	return DongleCred{App: app, Q: append([]byte{0x04}, pk...), CredID: id}, nil
}

func (d *fidoDongle) MakeCredential(app, user, pin string) (cred DongleCred, err error) {
	err = d.with(func(dev *C.fido_dev_t) error {
		c := C.fido_cred_new()
		if c == nil {
			return errors.New("dongle: out of memory")
		}
		defer C.fido_cred_free(&c)
		cdh := make([]byte, 32)
		if _, err := rand.Read(cdh); err != nil {
			return err
		}
		uid := make([]byte, 32)
		if _, err := rand.Read(uid); err != nil {
			return err
		}
		capp, cuser := C.CString(app), C.CString(user)
		defer C.free(unsafe.Pointer(capp))
		defer C.free(unsafe.Pointer(cuser))
		if err := fidoErr("cred type", C.fido_cred_set_type(c, coseES256)); err != nil {
			return err
		}
		if err := fidoErr("cred rp", C.fido_cred_set_rp(c, capp, nil)); err != nil {
			return err
		}
		if err := fidoErr("cred user", C.fido_cred_set_user(c, cbytes(uid), C.size_t(len(uid)), cuser, nil, nil)); err != nil {
			return err
		}
		if err := fidoErr("cred hash", C.fido_cred_set_clientdata_hash(c, cbytes(cdh), C.size_t(len(cdh)))); err != nil {
			return err
		}
		if err := fidoErr("cred rk", C.fido_cred_set_rk(c, C.FIDO_OPT_TRUE)); err != nil {
			return err
		}
		// credProtect level 3: the dongle will not even list or use the key
		// without the PIN — the "verify-required" of `ssh-keygen -O verify-required`.
		if err := fidoErr("cred protect", C.fido_cred_set_prot(c, fidoCredProtUVRequired)); err != nil {
			return err
		}
		cpin, free := cstrOrNil(pin)
		defer free()
		if err := fidoErr("make credential", C.fido_dev_make_cred(dev, c, cpin)); err != nil {
			return err
		}
		cred, err = credFrom(app, c)
		return err
	})
	return
}

func (d *fidoDongle) Credentials(app, pin string) (creds []DongleCred, err error) {
	err = d.with(func(dev *C.fido_dev_t) error {
		rk := C.fido_credman_rk_new()
		if rk == nil {
			return errors.New("dongle: out of memory")
		}
		defer C.fido_credman_rk_free(&rk)
		capp := C.CString(app)
		defer C.free(unsafe.Pointer(capp))
		cpin, free := cstrOrNil(pin)
		defer free()
		r := C.fido_credman_get_dev_rk(dev, capp, rk, cpin)
		if r == fidoErrNoCredentials {
			return nil
		}
		if err := fidoErr("list credentials", r); err != nil {
			return err
		}
		for i := C.size_t(0); i < C.fido_credman_rk_count(rk); i++ {
			c, err := credFrom(app, (*C.fido_cred_t)(unsafe.Pointer(C.fido_credman_rk(rk, i))))
			if err != nil {
				continue // a non-ES256 key under the same rp is not ours
			}
			creds = append(creds, c)
		}
		return nil
	})
	return
}

func (d *fidoDongle) Assert(cred DongleCred, cdh [32]byte, pin string) (a Assertion, err error) {
	err = d.with(func(dev *C.fido_dev_t) error {
		as := C.fido_assert_new()
		if as == nil {
			return errors.New("dongle: out of memory")
		}
		defer C.fido_assert_free(&as)
		capp := C.CString(cred.App)
		defer C.free(unsafe.Pointer(capp))
		if err := fidoErr("assert rp", C.fido_assert_set_rp(as, capp)); err != nil {
			return err
		}
		if err := fidoErr("assert hash", C.fido_assert_set_clientdata_hash(as, (*C.uchar)(unsafe.Pointer(&cdh[0])), 32)); err != nil {
			return err
		}
		if len(cred.CredID) > 0 {
			if err := fidoErr("assert cred", C.fido_assert_allow_cred(as, cbytes(cred.CredID), C.size_t(len(cred.CredID)))); err != nil {
				return err
			}
		}
		if err := fidoErr("assert up", C.fido_assert_set_up(as, C.FIDO_OPT_TRUE)); err != nil {
			return err
		}
		cpin, free := cstrOrNil(pin)
		defer free()
		if err := fidoErr("get assertion", C.fido_dev_get_assert(dev, as, cpin)); err != nil {
			return err
		}
		if C.fido_assert_count(as) != 1 {
			return errors.New("dongle: expected one assertion")
		}
		a = Assertion{
			Flags:   byte(C.fido_assert_flags(as, 0)),
			Counter: uint32(C.fido_assert_sigcount(as, 0)),
			DERSig:  C.GoBytes(unsafe.Pointer(C.fido_assert_sig_ptr(as, 0)), C.int(C.fido_assert_sig_len(as, 0))),
		}
		return nil
	})
	return
}
