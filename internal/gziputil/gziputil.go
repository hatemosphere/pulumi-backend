package gziputil

import (
	"bytes"
	"errors"
	"io"
	"sync"

	"github.com/klauspost/compress/gzip"
)

var GzipWriterPool = sync.Pool{
	New: func() any { return gzip.NewWriter(nil) },
}

var BufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

const maxDecompressedSize = 512 * 1024 * 1024 // 512 MB

// Compress gzip-compresses data using pooled writers and buffers.
func Compress(data []byte) ([]byte, error) {
	buf := BufPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.Grow(len(data) / 4)

	gw := GzipWriterPool.Get().(*gzip.Writer)
	gw.Reset(buf)

	if _, err := gw.Write(data); err != nil {
		gw.Reset(nil)
		GzipWriterPool.Put(gw)
		BufPool.Put(buf)
		return nil, err
	}
	if err := gw.Close(); err != nil {
		gw.Reset(nil)
		GzipWriterPool.Put(gw)
		BufPool.Put(buf)
		return nil, err
	}

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())

	gw.Reset(nil)
	GzipWriterPool.Put(gw)
	BufPool.Put(buf)
	return result, nil
}

// Decompress decompresses gzip data with a 512 MB size limit.
func Decompress(data []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	limit := int64(maxDecompressedSize)
	limitReader := io.LimitReader(gr, limit+1)

	buf := BufPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.Grow(len(data) * 4)

	_, err = io.Copy(buf, limitReader)
	if err != nil {
		BufPool.Put(buf)
		return nil, err
	}
	if int64(buf.Len()) > limit {
		BufPool.Put(buf)
		return nil, errors.New("decompressed deployment exceeds maximum size of 512MB")
	}

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	BufPool.Put(buf)
	return result, nil
}

// MaybeDecompress decompresses data if it starts with gzip magic bytes, otherwise returns as-is.
func MaybeDecompress(data []byte) ([]byte, error) {
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		return Decompress(data)
	}
	return data, nil
}

// IsGzipped returns true if data starts with gzip magic bytes.
func IsGzipped(data []byte) bool {
	return len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b
}
