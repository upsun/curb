//go:build linux

package sandbox

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateSocketPair(t *testing.T) {
	parent, child, err := CreateSocketPair()
	require.NoError(t, err)
	defer parent.Close()
	defer child.Close()

	assert.Greater(t, int(parent.Fd()), 2)
	assert.Greater(t, int(child.Fd()), 2)
}

func TestSendRecvFD(t *testing.T) {
	parent, child, err := CreateSocketPair()
	require.NoError(t, err)
	defer parent.Close()
	defer child.Close()

	// Create a pipe as a test fd to send.
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	defer w.Close()

	// Send the write end from child to parent.
	err = SendFD(child, int(w.Fd()))
	require.NoError(t, err)

	// Receive it on the parent side.
	fd, err := RecvFD(parent)
	require.NoError(t, err)
	assert.Greater(t, fd, 0)

	// Write through the received fd and read from original read end.
	received := os.NewFile(uintptr(fd), "received")
	defer received.Close()

	_, err = received.Write([]byte("hello"))
	require.NoError(t, err)

	buf := make([]byte, 5)
	n, err := r.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf[:n]))
}
