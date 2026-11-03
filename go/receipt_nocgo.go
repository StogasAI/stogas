//go:build !cgo

package stogas

// RequestDigest requires the native verification core.
func RequestDigest([]byte) (ContentDigest, error) {
	return ContentDigest{}, ErrNativeLibraryUnavailable
}

// ResponseDigest requires the native verification core.
func ResponseDigest([]byte) (ContentDigest, error) {
	return ContentDigest{}, ErrNativeLibraryUnavailable
}

// StreamContent requires the native verification core.
type StreamContent struct{}

func NewStreamContent() *StreamContent   { return &StreamContent{} }
func (*StreamContent) Push([]byte) error { return ErrNativeLibraryUnavailable }
func (*StreamContent) Digest() (ContentDigest, error) {
	return ContentDigest{}, ErrNativeLibraryUnavailable
}
func (*StreamContent) Close() {}
