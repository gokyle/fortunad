// fortunad presents a TCP server that can deliver random data. It uses
// the Fortuna PRNG seeded with data from crypto/rand.Reader and the
// TPM.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"github.com/gokyle/fortunad/fortuna"
	"github.com/gokyle/tpm"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	prng           *fortuna.Fortuna
	tpmCtx         *tpm.TPMContext
	tpmSource      *fortuna.SourceWriter
	devRandSource  *fortuna.SourceWriter
	connTimeSource *fortuna.SourceWriter
	shutdownChan   = make(chan interface{}, 0)
	seedFile       = "fortunad.seed"
	entropyChan    = make(chan int64, 4)
)

// The Fortuna PRNG requires identifiers for each source. These are
// represented as single bytes.
const (
	SourceTPM byte = iota + 1
	SourceDevRand
	SourceConnTime
)

// readLimit is the number of bytes in a chunk copied over.
const readLimit int64 = 4096

// copyFromPRNG is a modification of the io.Copy function. In this
// case, none of the interfaces is a WriterTo or ReaderFrom; it's
// also important that the amount of random data that has been written
// out be regularly added to the PRNG tally so that it the PRNG may
// be stirred as required.
func copyFromPRNG(dst io.Writer) (written int64, err error) {
	buf := make([]byte, readLimit)
	for {
		nr, er := prng.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			err = er
			break
		}
		entropyChan <- int64(nr)
	}
	return written, err
}

// Initialise the PRNG, TPM, and add initial entropy from host and TPM.
func setup() {
	log.Println("initialising PRNG and TPM")
	if _, err := os.Stat(seedFile); err == nil {
		log.Printf("seed file found; loading PRNG state from %s",
			seedFile)
		prng, err = fortuna.FromSeed(seedFile)
		if err != nil {
			log.Fatalf("%v", err)
		}
	} else {
		log.Println("no seed file found, initialising new PRNG")
		prng = fortuna.New()
	}
	tpmSource = fortuna.NewSourceWriter(prng, SourceTPM)
	devRandSource = fortuna.NewSourceWriter(prng, SourceDevRand)
	connTimeSource = fortuna.NewSourceWriter(prng, SourceConnTime)

	var err error
	tpmCtx, err = tpm.NewTPMContext()
	if err != nil {
		log.Fatalf("%v", err)
	}
	err = refillPRNG()
	if err != nil {
		log.Fatalf("%v", err)
	}
}

// refillPRNG reloads the PRNG with entropy. It reads 1024 bytes from
// crypto/rand.Reader and 1024 bytes from the TPM. Finally, the nanosecond
// component of the current timestamp is written to the PRNG.
func refillPRNG() (err error) {
	log.Println("refilling pool (1/2)")
	// First fill of pool: each pool receives 16 bytes of entropy
	// from crypto/rand.Reader, and 16 bytes of entropy from the TPM.
	var event1 = make([]byte, 16)
	for i := 0; i < fortuna.PoolSize; i++ {
		_, err = io.ReadFull(rand.Reader, event1)
		if err != nil {
			log.Fatalf("%v", err)
		}
		_, err = devRandSource.Write(event1)
		if err != nil {
			log.Fatalf("%v", err)
		}

		var event2 []byte
		event2, err = tpmCtx.Random(16)
		if err != nil {
			log.Fatalf("%v", err)
		}
		_, err = tpmSource.Write(event2)
		if err != nil {
			log.Fatalf("%v", err)
		}
	}

	log.Println("refilling pool (2/2)")
	// Second fill: swap order of writes (TPM, then rand).
	for i := 0; i < fortuna.PoolSize; i++ {
		var event2 []byte
		event2, err = tpmCtx.Random(16)
		if err != nil {
			log.Fatalf("%v", err)
		}
		_, err = tpmSource.Write(event2)
		if err != nil {
			log.Fatalf("%v", err)
		}

		_, err = io.ReadFull(rand.Reader, event1)
		if err != nil {
			log.Fatalf("%v", err)
		}
		_, err = devRandSource.Write(event1)
		if err != nil {
			log.Fatalf("%v", err)
		}

	}

	writeTimestamp()
	return nil
}

// writeTimestamp takes the nanosecond component of the current
// timestamp, packs it as a 32-bit unsigned integer, and adds the
// SHA-256 digest of that to the PRNG state.
func writeTimestamp() {
	ns := uint32(time.Now().Nanosecond())
	var ts = make([]byte, 8)
	binary.BigEndian.PutUint32(ts, ns)
	sum := sha256.Sum256(ts)
	connTimeSource.Write(sum[:])
}

// Shutdown closes down the TPM interface and writes out a seed file.
func shutdown() {
	log.Println("shutting down")
	close(shutdownChan)
	close(entropyChan)
	err := tpmCtx.Destroy()
	if err != nil {
		log.Fatalf("TPM failed to shutdown: %v", err)
	}

	err = prng.WriteSeed(seedFile)
	if err != nil {
		log.Printf("failed to write seed file: %v", err)
	}
}

// logAutoUpdate runs the PRNG autoupdate functions. These write
// out the seed file every ten minutes and refill the PRNG after
// six hours.
func logAutoUpdate() {
	var fsErr = make(chan error, 4)
	prng.AutoUpdate(seedFile, shutdownChan, fsErr)
	go func() {
		for {
			err := <-fsErr
			log.Println("autoupdate error: %v", err)
		}
	}()

	go func() {
		for {
			select {
			case <-time.After(6 * time.Hour):
				refillPRNG()
			case _, ok := <-shutdownChan:
				if !ok {
					break
				}
			}
		}
		log.Println("autofill shutting down")
	}()
}

// server sets up the TCP socket and accepts incoming connections.
func server(addr string) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		shutdown()
		log.Fatal(err.Error())
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		shutdown()
		log.Fatal(err.Error())
	}

	log.Println("listening on", addr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err.Error())
		}
		writeTimestamp()
		go func() {
			_, err = copyFromPRNG(conn)
			if err != nil {
				log.Println(err.Error())
			}
			conn.Close()
		}()
	}
}

// entropyCheck keeps track of the amount of random data written
// out; after 2**32-1 bytes, it will stir the PRNG using rand.Reader
// and the TPM.
func entropyCheck() {
	var entropy int64
	var printCheck int64
	const regen int64 = 4294967295 // 2^32-1 bytes
	for {
		n, ok := <-entropyChan
		if !ok {
			break
		}
		entropy += n
		printCheck += n

		// 2 ** 32 bits
		if printCheck >= 536870912 {
			log.Printf("%d total bytes read from PRNG",
				entropy)
			printCheck = 0
		}

		if entropy >= regen {
			log.Println("stirring PRNG")
			refillPRNG()
			entropy = 0
		}
	}
}

func main() {
	addr := flag.String("a", "127.0.01:4141", "address server should listen on")
	seed := flag.String("f", seedFile, "path to seed file")
	flag.Parse()
	seedFile = *seed
	setup()
	logAutoUpdate()
	go entropyCheck()
	go server(*addr)
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Kill, os.Interrupt, syscall.SIGTERM)
	<-sigc
	shutdown()
}
