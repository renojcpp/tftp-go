package tftp

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ========= Server Structures =========

type Server struct {
	listener    net.Listener
	clientLimit *Clientlimit
	port        string
	rootPath    string
	ipAddress   string
}

type ServerConnection struct {
	server        *Server
	conn          net.Conn
	readWriter    bufio.ReadWriter
	id            int
	encryption    *EncryptionManager
	keysExchanged bool
}

// ========= Server Initialization =========

func NewServer(listener net.Listener, maxClients int, port string, rootPath string) *Server {
	if rootPath != "" {
		err := createRootDirectory(rootPath)
		if err != nil {
			log.Fatalf("Error creating server root directory")
		}
	}

	return &Server{
		listener:    listener,
		clientLimit: NewClientLimit(maxClients),
		port:        port,
		rootPath:    rootPath,
		ipAddress:   listener.Addr().String(),
	}
}

func createRootDirectory(rootDir string) error {
	if !filepath.IsAbs(rootDir) {
		absPath, err := filepath.Abs(rootDir)
		if err != nil {
			return fmt.Errorf("error getting absolute path: %v", err)
		}
		rootDir = absPath
	}

	err := os.MkdirAll(rootDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create or access root directory '%s': %v", rootDir, err)
	}

	return nil
}

// ========= Server Startup and Loop =========

func (s *Server) Start() {
	s.printAddresses()
	defer s.listener.Close()
	connID := 1
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		go s.handleConnection(conn, &connID)
	}
}

func (s *Server) handleConnection(conn net.Conn, connID *int) {
	defer conn.Close()
	if err := s.clientLimit.increaseClientCount(); err != nil {
		fmt.Println("Client limit has been reached!")
		errPacket := EncodeErr("client limit has been reached!")
		conn.Write(errPacket)
		return
	}
	defer s.clientLimit.decreaseClientCount()

	tftpConn, err := s.NewTFTPConnection(conn, *connID)
	if err != nil {
		fmt.Println("Error creating server connection:", err)
		return
	}
	*connID++

	if err := tftpConn.Handshake(); err != nil {
		fmt.Println("Handshake failed:", err)
		return
	}

	tftpConn.NextRequest()
}

// ========= Server Connection Initialization =========

func (s *Server) NewTFTPConnection(c net.Conn, id int) (*ServerConnection, error) {
	writer := bufio.NewWriter(c)
	reader := bufio.NewReader(c)

	encryption, err := NewEncryptionManager()
	if err != nil {
		log.Println("Error creating encryption manager")
		return nil, err
	}

	server := &ServerConnection{
		s,
		c,
		*bufio.NewReadWriter(reader, writer),
		id,
		encryption,
		false,
	}

	return server, nil
}

func (s *ServerConnection) Handshake() error {
	msg := "Hello!"
	packet := EncodeDAT(1, uint32(len(msg)), []byte(msg))

	_, err := s.conn.Write(packet)
	if err != nil {
		writeErr := &throwErrors{
			err, "writing handshake",
		}
		return writeErr
	}
	fmt.Println("Handshake Dat block # 1 sent")

	buf := make([]byte, 512)
	_, err = s.readWriter.Read(buf)

	if err != nil {
		readErr := &throwErrors{
			err, "reading handshake",
		}
		return readErr
	}

	decoded := Packet(buf)

	switch decoded.Type() {
	case ACK:
		fmt.Println("Handshake acknowledgement received")
		err := s.HandleKeyExchange()
		if err != nil {
			s.SendError(fmt.Sprintf("Key exchange failed: %v", err))
		}
		return nil
	default:
		s.conn.Close()
		return errors.New("unexpected block from handshake")
	}
}

// ========= Server Connection Request Loop =========

func (s *ServerConnection) NextRequest() {
	var decoded Packet
	var err error
	for {
		if !s.keysExchanged {
			buf := make([]byte, 1024)
			n, err := s.readWriter.Read(buf)
			if err != nil {
				if err == io.EOF {
					fmt.Fprintf(os.Stdout, "Connection closed. ID: %d\n", s.id)
				}
				break
			}
			decoded = Packet(buf[:n])
		} else {
			decoded, err = s.ReceivePacket()
			if err != nil {
				if err == io.EOF {
					fmt.Fprintf(os.Stdout, "Connection closed. ID: %d\n", s.id)
				}
				break
			}
		}

		switch decoded.Type() {
		case RRQ:
			rrq := RRQPacket(decoded)
			err = s.ReadReadRequest(rrq.Filename())
			if err != nil {
				fmt.Println("Error executing RRQ:", err)
			}
		case WRQ:
			wrq := WRQPacket(decoded)
			err = s.ReadWriteRequest(wrq.Filename())
			if err != nil {
				fmt.Println("Error executing WRQ:", err)
			}
		default:
			fmt.Fprintf(os.Stderr, "Unexpected header %d", decoded.Type())
			break
		}
	}
	s.conn.Close()
}

// ========= TFTP Request Handlers =========

func (s *ServerConnection) ReadWriteRequest(filename string) error {
	fmt.Println("Processing write request")
	file, err := os.OpenFile(s.server.rootPath+filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666)

	if err != nil {
		serverRWQErr := &throwErrors{
			err, "opening file",
		}
		return serverRWQErr
	}
	defer file.Close()

	var ackn uint32 = 0
	done := false
	for !done {
		ack := EncodeACK(ackn)
		err := s.SendPacket(ack)
		if err != nil {
			serverSendPackErr := &throwErrors{
				err, "server sending packet",
			}
			return serverSendPackErr
		}
		fmt.Println("Sending Acknowledgment block #", ackn)
		ackn += 1

		decoded, err := s.ReceivePacket()
		if err != nil {
			serverReceivePackErr := &throwErrors{
				err, "server receiving packet",
			}
			return serverReceivePackErr
		}

		switch decoded.Type() {
		case DAT:
			done, err = HandleDAT(decoded, ackn)
			if err != nil {
				serverHandleDATErr := &throwErrors{
					err, "server handling data",
				}
				s.conn.Close()
				return serverHandleDATErr
			}
			d := DATPacket(decoded)
			err = binary.Write(file, binary.NativeEndian, d.Data())
			if err != nil {
				serverWriteErr := &throwErrors{
					err, "server writing",
				}
				return serverWriteErr
			}
			fmt.Println("Data written block #", ackn)
		default:
			errs := "unexpected header"
			s.SendError(errs)
			return errors.New(errs)
		}
		if done {
			ack := EncodeACK(ackn)
			err := s.SendPacket(ack)
			if err != nil {
				serverACKWriteErr := &throwErrors{
					err, "server ACK and writing",
				}
				return serverACKWriteErr
			}
			fmt.Println("Sending Acknowledgment block #", ackn)
			fmt.Println("Write request fulfilled. End of data stream.")
		}
	}

	return nil
}

func (s *ServerConnection) ReadReadRequest(filename string) error {
	fmt.Println("Processing read request")
	var buf bytes.Buffer

	if len(filename) == 0 {
		var path string
		if(s.server.rootPath == ""){
			path = "."
		}else{
			path = s.server.rootPath
		}
		files, err := os.ReadDir(path)
		if err != nil {
			readDirErr := &throwErrors{
				err, "server reading directory",
			}
			return readDirErr
		}

		for _, file := range files {
			listing, err := buildDirectoryListing(file, s.server.rootPath)
			if err != nil {
				buildDirErr := &throwErrors{
					err, "server building directory",
				}
				return buildDirErr
			}
			buf.WriteString(listing)
			buf.WriteByte('\n')
		}
	} else {
		file, err := os.ReadFile(s.server.rootPath + filename)
		if err != nil {
			s.SendError(err.Error())
			return &throwErrors{
				err, "read file",
			}
		}
		buf.Write(file)
	}

	stream := NewDATStream(&buf)

	done := false
	var blockn uint32 = 1
	for !done {
		next, err := stream.Next()
		if err != nil {
			s.SendError(err.Error())
			return err
		}
		err = s.SendPacket(Packet(next))

		if err != nil {
			sendPackErr := &throwErrors{
				err, "sending packet",
			}
			return sendPackErr
		}
		fmt.Println("Sending Data block #", blockn)

		if len(next.Data()) < 512 {
			done = true
		}
		decoded, err := s.ReceivePacket()
		if err != nil {
			receivePackErr := &throwErrors{
				err, "receiving packet",
			}
			return receivePackErr
		}

		switch decoded.Type() {
		case ACK:
			ack := ACKPacket(decoded)

			if ack.Block() != blockn {
				errs := fmt.Sprintf("Unexpected block number %d", ack.Block())
				s.SendError(errs)
				s.conn.Close()
				return errors.New(errs)
			}
			fmt.Println("Acknowledge received for block #", blockn)
		default:
			errs := fmt.Sprintf("Unexpected header %s", decoded.Type().String())
			s.SendError(errs)
			s.conn.Close()
			return errors.New(errs)
		}
		if done {
			fmt.Println("Read Request fulfilled. End of data stream.")
		}
		blockn++
	}

	return nil
}

// ========= Send / Receive Functions =========

func (s *ServerConnection) SendPacket(packet Packet) error {
	encryptedPacket, err := encryptPacket(packet, s.encryption.sharedKey)
	if err != nil {
		encryptPackErr := &throwErrors{
			err, "encrypting packet",
		}
		return encryptPackErr
	}
	_, err = s.conn.Write(encryptedPacket)
	if err != nil {
		sendPackErr := &throwErrors{
			err, "sending packet",
		}
		return sendPackErr
	}
	return nil
}

func (s *ServerConnection) ReceivePacket() (Packet, error) {
	buf := make([]byte, 1024)
	n, err := s.readWriter.Read(buf)
	if err != nil {
		readPackErr := &throwErrors{
			err, "reading packet",
		}
		return nil, readPackErr
	}
	packet, err := decryptPacket(buf[:n], s.encryption.sharedKey)
	if err != nil {
		decryptPackErr := &throwErrors{
			err, "decrypting packet",
		}
		return nil, decryptPackErr
	}
	return Packet(packet), nil
}

func (s *ServerConnection) SendError(str string) error {
	errp := EncodeErr(str)
	err := s.SendPacket(errp)
	if err != nil {
		return fmt.Errorf("error sending err packet: %w", err)
	}
	return nil
}

// ========= Utility Functions =========

// Used in ReadReadRequest
func buildDirectoryListing(file os.DirEntry, rootPath string) (string, error) {
	var builder strings.Builder

	info, err := os.Stat(rootPath + file.Name())
	if err != nil {
		fmt.Println("Error accessing file:", err)
		return "", err
	}
	builder.WriteString(info.Mode().String())
	builder.WriteString(fmt.Sprintf("%10d", info.Size()))
	builder.WriteString(" ")
	builder.WriteString(info.ModTime().Format(time.RFC822))
	builder.WriteString(" ")
	builder.WriteString(file.Name())

	return builder.String(), nil
}

// Used in server.Start()
func (s *Server) printAddresses() {
	address := s.ipAddress
	var ipPart, portPart string

	if strings.HasPrefix(address, "[") {
		parts := strings.SplitN(address, "]", 2)
		ipPart = parts[0][1:]
		portPart = parts[1][1:]
	} else {
		parts := strings.Split(address, ":")
		ipPart = parts[0]
		portPart = parts[1]
	}

	if ipPart == "::" {
		interfaces, _ := net.Interfaces()

		fmt.Println("Server is broadcasting at the following addresses:")
		for _, iface := range interfaces {
			addrs, _ := iface.Addrs()

			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}

				if !ip.IsLoopback() {
					fmt.Printf("%s on port %s\n", ip.String(), portPart)
				}
			}
		}
	} else {
		fmt.Printf("Server Listening at %s on port %s\n", ipPart, portPart)
	}
	fmt.Println()
}

// ========= Key Exchange Functions =========
// Used in handshake
func (s *ServerConnection) HandleKeyExchange() error {
	if err := s.StartKeyExchange(); err != nil {
		log.Println("Error starting key exchange")
		return err
	}

	encryptedSymmetricKey := make([]byte, 256)
	n, err := s.readWriter.Read(encryptedSymmetricKey)
	if err != nil {
		return fmt.Errorf("failed to read encrypted key from client: %w", err)
	}

	encryptedSymmetricKey = encryptedSymmetricKey[:n]
	decryptedSymmetricKey, err := rsaDecrypt(s.encryption.privateKey, encryptedSymmetricKey)
	if err != nil {
		return fmt.Errorf("decryption of symmetric key failed: %w", err)
	}

	s.encryption.sharedKey = decryptedSymmetricKey

	fmt.Printf("Key exchange completed successfully with connection id: %d\n\n", s.id)
	s.keysExchanged = true
	return nil
}

func (s *ServerConnection) StartKeyExchange() error {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&s.encryption.privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	_, err = s.conn.Write(publicKeyPEM)
	return err
}

func (s *ServerConnection) CompleteKeyExchange() error {
	encryptedSymmetricKey := make([]byte, 256)
	n, err := s.readWriter.Read(encryptedSymmetricKey)
	if err != nil {
		rsaEncyptErr := &throwErrors{
			err, "encrypting key",
		}
		return rsaEncyptErr
	}

	symmetricKey, err := rsaDecrypt(s.encryption.privateKey, encryptedSymmetricKey[:n])
	if err != nil {
		rsaDeCryptErr := &throwErrors{
			err, "decrypting key",
		}
		return rsaDeCryptErr
	}

	s.encryption.sharedKey = symmetricKey
	return nil
}
