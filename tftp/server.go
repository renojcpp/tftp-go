package tftp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"log"
	"time"
	"syscall"
	"strings"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
)

type Server struct {
	listener    net.Listener
	clientLimit *Clientlimit
	port        string
	rootPath	string
}

// todo: need to send errpackets
type ServerConnection struct {
	server *Server
	conn       net.Conn
	readWriter bufio.ReadWriter
	id         int
	encryption *EncryptionManager
	keysExchanged bool
}

func NewServer(listener net.Listener, maxClients int, port string, rootPath string) *Server {
	if rootPath != ""{
		err := createRootDirectory(rootPath)
		if err != nil{
			log.Fatalf("Error creating server root directory")
		}
	}
	
	return &Server{
		listener:    listener,
		clientLimit: NewClientLimit(maxClients),
		port:        port,
		rootPath: rootPath,
	}
}

func createRootDirectory(rootDir string) error{
	if !filepath.IsAbs(rootDir) {
        absPath, err := filepath.Abs(rootDir)
        if err != nil {
            return fmt.Errorf("error getting absolute path: %v", err)
        }
        rootDir = absPath
    }

    err := os.MkdirAll(rootDir, 0755)
    if err != nil {
        return fmt.Errorf("Failed to create or access root directory '%s': %v", rootDir, err)
    }

	return nil
}


func(s *Server) NewTFTPConnection(c net.Conn, id int) (*ServerConnection, error) {
	writer := bufio.NewWriter(c)
	reader := bufio.NewReader(c)

	encryption, err := NewEncryptionManager()
	if err != nil{
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

func (s *ServerConnection) SendError(str string) error {
	errp := EncodeErr(str)
	err := s.SendPacket(errp)
	if err != nil{
		return fmt.Errorf("Error sending err packet: ", err)
	}
	return nil
}

func (s *ServerConnection) ReadWriteRequest(filename string) error {	
	fmt.Println("Processing read request")
	// path := filepath.Join(s.server.rootPath, filename)
	file, err := os.OpenFile(s.server.rootPath + filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666)

	defer file.Close()
	if err != nil {
		fmt.Println(err)
		return err
	}

	var ackn uint32 = 0
	done := false
	for !done {
		ack := EncodeACK(ackn)
		err := s.SendPacket(ack)
		if err != nil {
			return err
		}
		fmt.Println("Sending Acknowledgment block #", ackn)

		if err != nil {
			return err
		}

		ackn += 1

		decoded, err := s.ReceivePacket()
		if err != nil {
			return err
		}

		switch decoded.Type() {
		case DAT:
			done, err = HandleDAT(decoded, ackn)
			if err != nil {
				fmt.Println(err)
				return err
			}
			d := DATPacket(decoded)
			err = binary.Write(file, binary.NativeEndian, d.Data())
			if err != nil {
				return err
			}
			fmt.Println("Data written block #", ackn)
		default:
			errs := "Unexpected header"
			s.SendError(errs)
			return errors.New(errs)
		}
		if done{
			ack := EncodeACK(ackn)
			err := s.SendPacket(ack)
			if err != nil {
				return err
			}
			fmt.Println("Sending Acknowledgment block #", ackn)
			fmt.Println("Write request fulfilled. End of data stream.")
		}
	}

	return nil
}

func (s *ServerConnection) Handshake() error {
	msg := "Hello!"
	packet := EncodeDAT(1, uint32(len(msg)), []byte(msg))

	_, err := s.conn.Write(packet)
	if err != nil {
		return err
	}
	fmt.Println("Handshake dat block # 1 sent")

	buf := make([]byte, 512)
	_, err = s.readWriter.Read(buf)

	if err != nil {
		return err
	}

	decoded := Packet(buf)

	switch decoded.Type() {
	case ACK:
		fmt.Println("Handshake Acknowledgement Received")
		return nil
	default:
		return errors.New("Unexpected block from handshake")
	}
}

func returnUserIdentifiers(fileInfo os.FileInfo) (string, string){
	//might not work on all operating systems if encountering windows problems
	//comment out the use of this function and its returns in RRQ function

	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		log.Fatal("Failed to extract file system info")
	}	
	uid := stat.Uid 
	gid := stat.Gid 
	userInfo, err := user.LookupId(fmt.Sprintf("%d", uid))
	if err != nil {
		log.Fatal("Error looking up user:", err)
	}

	groupInfo, err := user.LookupGroupId(fmt.Sprintf("%d", gid))
	if err != nil {
		log.Fatal("Error looking up group:", err)
	}

	return userInfo.Username, groupInfo.Name
}

func buildDirectoryListing(file os.DirEntry) (string, error){
	var builder strings.Builder

	info, err := os.Stat(file.Name())
	if err != nil {
		fmt.Println("Error accessing file:", err)
		return "", err
	}
	builder.WriteString(info.Mode().String())
	//Comment userID, groupID lines if not running on windows
	userID, groupID := returnUserIdentifiers(info)
	builder.WriteString("  ")
	builder.WriteString(userID)
	builder.WriteString(" ")
	builder.WriteString(groupID)
	builder.WriteString(" ")
	builder.WriteString(fmt.Sprintf("%10d", info.Size()))
	builder.WriteString(" ")
	builder.WriteString(info.ModTime().Format(time.RFC822))
	builder.WriteString(" ")
	builder.WriteString(file.Name())

	return builder.String(), nil
}

func (s *ServerConnection) ReadReadRequest(filename string) error {
	fmt.Println("Processing read request")
	var buf bytes.Buffer

	if len(filename) == 0 {
		files, err := os.ReadDir(".")
		if err != nil {
			return err
		}

		for _, file := range files {
			listing, err := buildDirectoryListing(file)
			if err != nil{
				return err
			}
			buf.WriteString(listing)
			buf.WriteByte('\n')
		}
	} else {
		file, err := os.ReadFile(filename)
		if err != nil {
			s.SendError(err.Error())
			return err
		}
		buf.Write(file)
	}

	stream := NewDATStream(&buf)

	done := false
	var blockn uint32 = 1
	for !done {
		next, err := stream.Next()
		err = s.SendPacket(Packet(next))

		
		if err != nil {
			return err
		}
		fmt.Println("Sending Data block #", blockn)

		//Need to fix this to handle empty file
		if len(next.Data()) < 512 {
			done = true
		}
		decoded, err := s.ReceivePacket()
		if err != nil {
			return err
		}

		switch decoded.Type() {
		case ACK:
			ack := ACKPacket(decoded)

			if ack.Block() != blockn {
				errs := fmt.Sprintf("Unexpected block number %d", ack.Block())
				s.SendError(errs)
				return errors.New(errs)
			}
			fmt.Println("Acknowledge received for block #", blockn)
		default:
			errs := fmt.Sprintf("Unexpected header %s", decoded.Type().String())
			s.SendError(errs)
			return errors.New(errs)
		}
		if done{
			fmt.Println("Read Request fulfilled. End of data stream.")
		}
		blockn++
	}

	return nil
}

func (s *ServerConnection) NextRequest() {
	var decoded Packet
	var err error
	for {
		//May want to modularize better. Conditional handles first uncencrypted packet
		if(!s.keysExchanged){
			buf := make([]byte, 1024)
			n, err := s.readWriter.Read(buf)
			if err != nil {
				if err == io.EOF {
					fmt.Fprintf(os.Stdout, "Connection closed\n")
				}
				break
			}
			decoded = Packet(buf[:n])
		} else{
			decoded, err = s.ReceivePacket()
			if err != nil {
				if err == io.EOF {
					fmt.Fprintf(os.Stdout, "Connection closed\n")
				}
				break
			}
		}

		switch decoded.Type() {
		case RRQ:
			rrq := RRQPacket(decoded)
			err = s.ReadReadRequest(rrq.Filename())
			if err != nil {
				// do something
			}
		case WRQ:
			wrq := WRQPacket(decoded)
			err = s.ReadWriteRequest(wrq.Filename())
		case KEY:
			err := s.HandleKeyExchange()
            if err != nil {
                s.SendError(fmt.Sprintf("Key exchange failed: %v", err))
            }
		default:
			//Ignoring connection check 0 byte, may need to refactor to make more robust
			if (decoded.Type() == 0){
				break
			}
			fmt.Fprintf(os.Stderr, "Unexpected header %d", decoded.Type())
		}
	}

	s.conn.Close()
}

// func StartServer(listener net.Listener, port string){
// 	fmt.Println("Server Listening on port " + port )
//     defer listener.Close()
//     for {
//         conn, err := listener.Accept()
//         if err != nil {
//             log.Println("Error accepting connection:", err)
//             continue
//         }

//         tftpConn, err := NewTFTPConnection(conn, 1)
// 		if err != nil{
// 			log.Println("Error creating server connection:", err)
// 		}
//         go tftpConn.NextRequest()
//     }
// }

func (s *Server) Start(){
	fmt.Println("Server Listening on port " + s.port )
    defer s.listener.Close()
    for {
        conn, err := s.listener.Accept()
        if err != nil {
            log.Println("Error accepting connection:", err)
            continue
        }
		if conn != nil && s.clientLimit.increaseClientCount() != nil {
			fmt.Println("Client limit has been reached!")
			continue
		}
        tftpConn, err := s.NewTFTPConnection(conn, 1)
		if err != nil{
			log.Println("Error creating server connection:", err)
		}

		if err := tftpConn.Handshake(); err != nil {
            log.Println("Handshake failed:", err)
            conn.Close()
            continue
        }
        go tftpConn.NextRequest()
    }
}




/*
Packet Sending and Encryption methods below
*/

func (s *ServerConnection) SendPacket(packet Packet) error {
	encryptedPacket, err := encryptPacket(packet, s.encryption.sharedKey)
	if err != nil {
		return err
	}
	_, err = s.conn.Write(encryptedPacket)
	if err != nil {
		return err
	}
	return nil
}


func (s *ServerConnection) ReceivePacket() (Packet, error) {
	buf := make([]byte, 1024)
	n, err := s.readWriter.Read(buf)
	if err != nil {
		return nil, err
	}
	packet, err := decryptPacket(buf[:n], s.encryption.sharedKey)
	if err != nil {
		return nil, err
	}
	return Packet(packet), nil
}


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

    fmt.Println("Key exchange completed successfully with connection id: ", s.id)
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
		return err
	}

	symmetricKey, err := rsaDecrypt(s.encryption.privateKey, encryptedSymmetricKey[:n])
	if err != nil {
		return err
	}

	s.encryption.sharedKey = symmetricKey
	return nil
}
