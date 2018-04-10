package ftps

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"
)

type FTPS struct {
	host string

	conn net.Conn
	text *textproto.Conn

	Debug     bool
	Timeout   time.Duration
	TLSConfig tls.Config
}

func (ftps *FTPS) Connect(host string, port int) (err error) {

	ftps.host = host

	ftps.conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), ftps.Timeout)
	if err != nil {
		return err
	}

	ftps.text = textproto.NewConn(ftps.conn)

	_, err = ftps.response(220)
	if err != nil {
		return err
	}

	_, err = ftps.request("AUTH TLS", 234)
	if err != nil {
		return err
	}

	ftps.conn = ftps.upgradeConnToTLS(ftps.conn)
	ftps.text = textproto.NewConn(ftps.conn) // TODO use sync or something similar?

	return
}

func (ftps *FTPS) isConnEstablished() {

	if ftps.conn == nil {
		panic("Connection is not established yet")
	}
}

func (ftps *FTPS) Login(username, password string) (err error) {

	ftps.isConnEstablished()

	_, err = ftps.request("LANG", 200) // encrypt data connection
	if err != nil {
		return err
	}

	_, err = ftps.request(fmt.Sprintf("USER %s", username), 331)
	if err != nil {
		return err
	}

	_, err = ftps.request(fmt.Sprintf("PASS %s", password), 230)
	if err != nil {
		return err
	}

	_, err = ftps.request("TYPE I", 200) // use binary mode
	if err != nil {
		return err
	}

	_, err = ftps.request("PBSZ 0", 200)
	if err != nil {
		return err
	}

	_, err = ftps.request("PROT P", 200) // encrypt data connection
	if err != nil {
		return err
	}

	return
}

func (ftps *FTPS) request(cmd string, expected int) (message string, err error) {

	ftps.isConnEstablished()

	ftps.debugInfo("<*cmd*> " + cmd)

	_, err = ftps.text.Cmd(cmd)
	if err != nil {
		return
	}

	message, err = ftps.response(expected)

	return
}

func (ftps *FTPS) requestDataConn(cmd string, expected []int) (dataConn net.Conn, err error) {

	port, err := ftps.pasv()
	if err != nil {
		return
	}

	dataConn, err = ftps.openDataConn(port)
	if err != nil {
		return nil, err
	}

	_, err = ftps.requestE(cmd, expected)
	if err != nil {
		dataConn.Close()
		return nil, err
	}

	dataConn = ftps.upgradeConnToTLS(dataConn)

	return
}

func (ftps *FTPS) response(expected int) (message string, err error) {

	ftps.isConnEstablished()

	code, message, err := ftps.text.ReadResponse(expected)

	ftps.debugInfo(fmt.Sprintf("<*code*> %d", code))
	ftps.debugInfo("<*message*> " + message)

	return
}

func (ftps *FTPS) upgradeConnToTLS(conn net.Conn) (upgradedConn net.Conn) {

	var tlsConn *tls.Conn
	tlsConn = tls.Client(conn, &ftps.TLSConfig)

	tlsConn.Handshake()
	upgradedConn = net.Conn(tlsConn)

	// TODO verify that TLS connection is established

	return
}

func (ftps *FTPS) pasv() (port int, err error) {

	message, err := ftps.request("PASV", 227)
	if err != nil {
		return 0, err
	}

	start := strings.Index(message, "(")
	end := strings.LastIndex(message, ")")

	if start == -1 || end == -1 {
		err = errors.New("Invalid PASV response format")
		return 0, err
	}

	pasvData := strings.Split(message[start+1:end], ",")

	portPart1, err := strconv.Atoi(pasvData[4])
	if err != nil {
		return 0, err
	}

	portPart2, err := strconv.Atoi(pasvData[5])
	if err != nil {
		return 0, err
	}

	// Recompose port
	port = int(portPart1)*256 + int(portPart2)

	return
}

func (ftps *FTPS) PrintWorkingDirectory() (directory string, err error) {

	directory, err = ftps.request("PWD", 257)
	return
}

func (ftps *FTPS) ChangeWorkingDirectory(path string) (err error) {

	_, err = ftps.request(fmt.Sprintf("CWD %s", path), 250)
	return
}

func (ftps *FTPS) MakeDirectory(path string) (err error) {

	_, err = ftps.request(fmt.Sprintf("MKD %s", path), 257)
	return
}

func (ftps *FTPS) DeleteFile(path string) (err error) {

	_, err = ftps.request(fmt.Sprintf("DELE %s", path), 250)
	return
}

func (ftps *FTPS) RemoveDirectory(path string) (err error) {

	_, err = ftps.request(fmt.Sprintf("RMD %s", path), 250)
	return
}

func (ftps *FTPS) List() (entries []Entry, err error) {

	// TODO add support for MLSD

	dataConn, err := ftps.requestDataConn("LIST -a", []int{150}) // TODO use also -L to resolve links?
	if err != nil {
		return
	}
	defer dataConn.Close()

	reader := bufio.NewReader(dataConn)
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}

		entry, err := ftps.parseEntryLine(line)
		entries = append(entries, *entry)
	}
	dataConn.Close()

	_, err = ftps.response(226)
	if err != nil {
		return
	}

	return
}

func (ftps *FTPS) parseEntryLine(line string) (entry *Entry, err error) {

	// TODO Function mostly copied from https://github.com/jlaffaye/ftp

	fields := strings.Fields(line)
	if len(fields) < 9 {
		return nil, errors.New("Unsupported line format.")
	}

	entry = &Entry{}

	// parse type
	switch fields[0][0] {
	case '-':
		entry.Type = EntryTypeFile
	case 'd':
		entry.Type = EntryTypeFolder
	case 'l':
		entry.Type = EntryTypeLink
	default:
		return nil, errors.New("Unknown entry type.")
	}

	// parse size
	size, err := strconv.ParseUint(fields[4], 10, 0)
	if err != nil {
		return nil, err
	}
	entry.Size = size

	// parse time
	var timeStr string
	if strings.Contains(fields[7], ":") { // this year
		thisYear, _, _ := time.Now().Date()
		timeStr = fmt.Sprintf("%s %s %s %s GMT", fields[6], fields[5], strconv.Itoa(thisYear)[2:4], fields[7])
	} else { // not this year
		timeStr = fmt.Sprintf("%s %s %s 00:00 GMT", fields[6], fields[5], fields[7][2:4])
	}
	t, err := time.Parse("_2 Jan 06 15:04 MST", timeStr)
	if err != nil {
		return nil, err
	}
	entry.Time = t // TODO set timezone

	// parse name
	entry.Name = strings.Join(fields[8:], " ")

	return
}

func (ftps *FTPS) requestE(cmd string, expected []int) (message string, err error) {

	ftps.isConnEstablished()

	ftps.debugInfo("<*cmd*> " + cmd)

	_, err = ftps.text.Cmd(cmd)
	if err != nil {
		return
	}

	message, err = ftps.responseE(expected)

	return
}

func (ftps *FTPS) responseE(expected []int) (message string, err error) {

	ftps.isConnEstablished()

	code, message, err := readResponse(ftps.text, expected)

	ftps.debugInfo(fmt.Sprintf("<*code*> %d", code))
	ftps.debugInfo("<*message*> " + message)

	return
}

func parseCodeLine(line string, ee []int) (code int, continued bool, message string, err error) {
	if len(line) < 4 || line[3] != ' ' && line[3] != '-' {
		err = textproto.ProtocolError("short response: " + line)
		return
	}
	continued = line[3] == '-'
	code, err = strconv.Atoi(line[0:3])
	if err != nil || code < 100 {
		err = textproto.ProtocolError("invalid response code: " + line)
		return
	}
	message = line[4:]
	ok := false
	for _, expectCode := range ee {
		if 1 <= expectCode && expectCode < 10 && code/100 != expectCode ||
			10 <= expectCode && expectCode < 100 && code/10 != expectCode ||
			100 <= expectCode && expectCode < 1000 && code != expectCode {
			ok = true
			break
		}
	}
	if !ok {
		err = &textproto.Error{code, message}
	}
	return
}

func (ftps *FTPS) StoreData(remoteFilepath string, data []byte) (err error) {
	dataConn, err := ftps.requestDataConn(fmt.Sprintf("STOR %s", remoteFilepath), []int{125, 150})
	if err != nil {
		return
	}
	defer dataConn.Close()

	count, err := dataConn.Write(data)
	if err != nil {
		return
	}
	dataConn.Close()

	if len(data) != count {
		return errors.New("file transfer not complete")
	}

	_, err = ftps.response(226)
	if err != nil {
		return
	}

	return
}

func readCodeLine(r *textproto.Conn, expectCode []int) (code int, continued bool, message string, err error) {
	line, err := r.ReadLine()
	if err != nil {
		return
	}
	return parseCodeLine(line, expectCode)
}

func readResponse(r *textproto.Conn, expectCode []int) (code int, message string, err error) {
	code, continued, message, err := readCodeLine(r, expectCode)
	multi := continued
	for continued {
		line, err := r.ReadLine()
		if err != nil {
			return 0, "", err
		}

		var code2 int
		var moreMessage string
		code2, continued, moreMessage, err = parseCodeLine(line, []int{0})
		if err != nil || code2 != code {
			message += "\n" + strings.TrimRight(line, "\r\n")
			continued = true
			continue
		}
		message += "\n" + moreMessage
	}
	if err != nil && multi && message != "" {
		// replace one line error message with all lines (full message)
		err = &textproto.Error{code, message}
	}
	return
}

func (ftps *FTPS) StoreFile(remoteFilepath string, f *os.File) (err error) {

	dataConn, err := ftps.requestDataConn(fmt.Sprintf("STOR %s", remoteFilepath), []int{125, 150})
	if err != nil {
		return
	}
	defer dataConn.Close()

	_, err = io.Copy(dataConn, f)
	if err != nil {
		return
	}

	if err = dataConn.Close(); err != nil {
		return
	}

	_, err = ftps.response(226)
	if err != nil {
		return
	}

	return
}

func (ftps *FTPS) RetrieveFile(remoteFilepath string, file *os.File) (err error) {

	dataConn, err := ftps.requestDataConn(fmt.Sprintf("RETR %s", remoteFilepath), []int{150})
	if err != nil {
		return
	}
	defer dataConn.Close()

	_, err = io.Copy(file, dataConn)
	if err != nil {
		return
	}
	dataConn.Close()

	_, err = ftps.response(226)
	if err != nil {
		return
	}

	return
}

func (ftps *FTPS) Quit() (err error) {

	_, err = ftps.request("QUIT", 221)
	if err != nil {
		return
	}
	ftps.conn.Close()

	return
}

func (ftps *FTPS) openDataConn(port int) (dataConn net.Conn, err error) {

	dataConn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ftps.host, port), ftps.Timeout)
	if err != nil {
		return
	}

	return
}

func (ftps *FTPS) debugInfo(message string) {

	if ftps.Debug {
		log.Println(message)
	}
}
