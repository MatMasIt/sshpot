package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"crypto/ecdh"

	"github.com/matmasit/sshpot/internal/passwordsecrets"
)

func main() {
	var (
		keyPath    = flag.String("key", "", "path to the X25519 private key PEM")
		inputPath  = flag.String("in", "", "input CSV path (default: stdin)")
		outputPath = flag.String("out", "", "output CSV path (default: stdout)")
	)
	flag.Parse()

	if *keyPath == "" {
		fatalf("missing required -key")
	}

	priv, err := passwordsecrets.LoadX25519PrivateKeyPEM(*keyPath)
	if err != nil {
		fatalf("load key: %v", err)
	}

	in, closeIn, err := openInput(*inputPath)
	if err != nil {
		fatalf("open input: %v", err)
	}
	defer closeIn()

	out, closeOut, err := openOutput(*outputPath)
	if err != nil {
		fatalf("open output: %v", err)
	}
	defer closeOut()

	if err := unsealCSV(in, out, priv); err != nil {
		fatalf("unseal csv: %v", err)
	}
}

func unsealCSV(in io.Reader, out io.Writer, priv *ecdh.PrivateKey) error {
	reader := csv.NewReader(in)
	reader.FieldsPerRecord = -1

	headers, err := reader.Read()
	if err != nil {
		return err
	}
	modeIndex, passwordIndex, hasHeader := csvSchema(headers)
	if !hasHeader {
		return fmt.Errorf("expected a header row with a mode column")
	}
	if err := writeCSVRecord(out, headers); err != nil {
		return err
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if len(record) <= passwordIndex || len(record) <= modeIndex {
			return fmt.Errorf("record has too few fields: %v", record)
		}
		password, err := passwordsecrets.DecryptPassword(record[modeIndex], priv, record[passwordIndex])
		if err != nil {
			return err
		}
		record[passwordIndex] = password
		if err := writeCSVRecord(out, record); err != nil {
			return err
		}
	}
}

func csvSchema(headers []string) (modeIndex, passwordIndex int, ok bool) {
	modeFound := false
	passwordFound := false
	for i, header := range headers {
		switch strings.TrimSpace(strings.ToLower(header)) {
		case "mode":
			modeIndex = i
			modeFound = true
		case "password":
			passwordIndex = i
			passwordFound = true
		case "timestamp":
			// header is present but not otherwise used
		}
	}
	if !modeFound || !passwordFound {
		return 0, 0, false
	}
	return modeIndex, passwordIndex, true
}

func openInput(path string) (io.Reader, func(), error) {
	if path == "" {
		return os.Stdin, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func writeCSVRecord(w io.Writer, record []string) error {
	for index, field := range record {
		if index > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}

		if _, err := io.WriteString(w, "\""); err != nil {
			return err
		}
		for i := 0; i < len(field); i++ {
			if field[i] == '"' {
				if _, err := io.WriteString(w, "\"\""); err != nil {
					return err
				}
				continue
			}
			if _, err := io.WriteString(w, field[i:i+1]); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, "\""); err != nil {
			return err
		}
	}

	_, err := io.WriteString(w, "\n")
	return err
}
