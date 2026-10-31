package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	qrcode "github.com/yeqown/go-qrcode/v2"
)

func TestQRRoundTrip(t *testing.T) {
	if os.Getenv("FILEDROP_QR") != "1" {
		t.Skip("set FILEDROP_QR=1 to decode the QR with macOS Vision and Swift")
	}
	const expected = "https://receiver.example-tailnet.ts.net/#qr-roundtrip-example"
	code, err := qrcode.New(expected)
	if err != nil {
		t.Fatal(err)
	}
	writer := &qrPNG{}
	if err := code.Save(writer); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "qr.png")
	if err := os.WriteFile(path, writer.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	const script = `
import Foundation
import Vision
let request = VNDetectBarcodesRequest()
request.symbologies = [.qr]
let handler = VNImageRequestHandler(url: URL(fileURLWithPath: CommandLine.arguments[1]), options: [:])
try handler.perform([request])
guard let results = request.results, results.count == 1,
      let payload = results[0].payloadStringValue else {
    fatalError("Expected exactly one readable QR code")
}
print(payload)
`
	output, err := exec.Command("swift", "-e", script, path).CombinedOutput()
	if err != nil {
		t.Fatalf("native QR decoder failed: %v\n%s", err, output)
	}
	if strings.TrimSpace(string(output)) != expected {
		t.Fatalf("QR did not preserve the invitation URL: %s", output)
	}
}
