package main

import (
	"crypto/tls"
	"io"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
)

// rawCodec overrides the default proto codec so the server accepts
// any byte sequence without proto decoding, keeping streams alive longer.
// This exercises the transport-layer recvBuffer.put() path (CVE-2026-84304).
type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) {
	if b, ok := v.([]byte); ok {
		return b, nil
	}
	return []byte{}, nil
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	if b, ok := v.(*[]byte); ok {
		*b = data
	}
	return nil
}

func (rawCodec) Name() string { return "proto" }

func init() {
	encoding.RegisterCodec(rawCodec{})
}

// streamHandler simulates realistic per-message work by retaining a 200-byte
// allocation per received message — mirroring the struct-metadata amplification
// described in CVE-2026-84304 (1-byte payload → ~200 bytes server-side overhead).
// Buffers are released only when the stream closes, so they accumulate while
// the attacker keeps the stream open.
func streamHandler(_ any, stream grpc.ServerStream) error {
	var buf []byte
	var held [][]byte // retained per-message allocations
	for {
		if err := stream.RecvMsg(&buf); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		// Retain 200 bytes per message to model recvMsg struct overhead.
		overhead := make([]byte, 200)
		held = append(held, overhead)
	}
}

var echoServiceDesc = grpc.ServiceDesc{
	ServiceName: "echo.Echo",
	HandlerType: (*any)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "BidiStream",
			Handler:       func(srv any, stream grpc.ServerStream) error { return streamHandler(srv, stream) },
			ServerStreams: true,
			ClientStreams: true,
		},
	},
}

func main() {
	cert, err := tls.LoadX509KeyPair("/certs/server.crt", "/certs/server.key")
	if err != nil {
		log.Fatalf("tls: %v", err)
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	srv := grpc.NewServer(grpc.Creds(creds))
	srv.RegisterService(&echoServiceDesc, struct{}{})

	lis, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Println("grpc-go v1.68.1 server listening on :443/tcp (TLS)")
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
