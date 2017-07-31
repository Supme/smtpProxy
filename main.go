package main

import (
	"net"
	"github.com/siebenmann/smtpd"
	"os"
	"log"
	"io"
	"fmt"
	"github.com/BurntSushi/toml"
	"path/filepath"
	"github.com/supme/directEmail"
)

var config struct{
	AllowIp []string `toml:"allow_ip"`
	Port string `toml:"port"`
	LogDir string `toml:"log_dir"`
	MapIp map[string]string `toml:"map_ip"`
	Debug    bool `toml:"debug"`
}

var mlog *log.Logger

type message struct {
	ip net.Addr
	mailFrom string
	rcptTo string
	data string
}

func main() {
	if _, err := toml.DecodeFile("config.toml", &config); err != nil {
		fmt.Println(err)
		return
	}

	os.MkdirAll(config.LogDir, os.FileMode(0700))
	l, err := os.OpenFile(filepath.Join(config.LogDir, "smtpProxy.log"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("error opening log file: %v", err)
	}
	defer l.Close()
	lg := io.MultiWriter(l, os.Stdout)
	mlog = log.New(lg, "", log.Ldate|log.Ltime)

	ln, err := net.Listen("tcp", ":" + config.Port)
	if err != nil {
		mlog.Println(err)
	}
	mlog.Println("Listen on port " + config.Port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			mlog.Println(err)
		}
		go connection(conn, nil)
	}
}

func connection(conn net.Conn, lg io.Writer) {
	defer conn.Close()

	allow := false
	remoteIp,_, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		mlog.Println(err)
	}
	for i := range config.AllowIp {
		if config.AllowIp[i] == remoteIp {
			allow = true
			continue
		}
	}
	if !allow {
		mlog.Printf("Deny connect from IP %s", remoteIp)
		return
	}

	var msg message
	cfg := smtpd.Config{}
	c := smtpd.NewConn(conn, cfg, lg)

	msg.ip = conn.LocalAddr()

	var event smtpd.EventInfo

	for {
		event = c.Next()
		if event.What == smtpd.ABORT {
			c.Reject()
			break
		}

		if event.What == smtpd.AUTHABORT {
			c.Reject()
			break
		}

		if event.What == smtpd.TLSERROR {
			c.Reject()
			break
		}

		if event.What == smtpd.AUTHRESP {
			c.Authenticate(func(con *smtpd.Conn, inp []byte) {
				con.AuthChallenge(inp)
			})
			continue
		}

		if event.What == smtpd.COMMAND {
			switch event.Cmd {
			case smtpd.MAILFROM:
				msg.mailFrom = event.Arg
			case smtpd.RCPTTO:
				msg.rcptTo = event.Arg
			}
			c.Accept()
			continue
		}

		if event.What == smtpd.GOTDATA {
			msg.data = event.Arg
			err := msg.send()
			errString := "Ok"
			if err != nil {
				errString = err.Error()
			}
			mlog.Printf("Mail from <%s> to <%s> result: %s", msg.mailFrom, msg.rcptTo, errString)
			if err != nil {
				_, err = conn.Write([]byte(err.Error() + "\r\n"))
				if err != nil {
					mlog.Println(err)
				}
				break
			} else {
				c.Accept()
			}
			continue
		}

		if event.What == smtpd.DONE {
			c.Accept()
			break
		}
	}
	return
}

func (msg *message) send() error {
	email := directEmail.New()
	email.Ip = msg.ip.String()
	email.MapIp = config.MapIp
	email.FromEmail = msg.mailFrom
	email.ToEmail = msg.rcptTo
	email.MapIp = config.MapIp
	email.SetRawMessageString(msg.data)
	return email.Send()
}

//func (msg *message) send() error {
//
//	var myGlobalIP string
//	myIp,_, err := net.SplitHostPort(msg.ip.String())
//	myGlobalIP, ok := config.MapIp[myIp]
//	if !ok {
//		myGlobalIP = myIp
//	} else if config.Debug {
//		mlog.Printf("Local IP address '%s' change to '%s'\n", myIp, myGlobalIP)
//	}
//
//	name, err := net.LookupAddr(myGlobalIP)
//	if err != nil && len(name) < 1 {
//		return err
//	}
//
//	splitEmail := strings.SplitN(msg.rcptTo, "@", 2)
//	if len(splitEmail) != 2 {
//		return errors.New("550 Bad email")
//	}
//
//	domain, err := idna.ToASCII(splitEmail[1])
//	if err != nil {
//		return errors.New(fmt.Sprintf("550 Domain name failed: %v", err))
//	}
//
//	addr := &net.TCPAddr{
//		IP: net.ParseIP(msg.ip.String()),
//	}
//	iface := net.Dialer{LocalAddr: addr}
//
//	record, err := net.LookupMX(domain)
//	if err != nil {
//		return errors.New(fmt.Sprintf("550 %v", err))
//	}
//
//	var (
//		conn net.Conn
//		server string
//	)
//	for i := range record {
//		server = strings.TrimRight(strings.TrimSpace(record[i].Host), ".")
//		conn, err = iface.Dial("tcp", net.JoinHostPort(server, "25"))
//		if err == nil {
//			break
//		}
//	}
//	if err != nil {
//		return errors.New(fmt.Sprintf("550 %v", err))
//	}
//	conn.SetDeadline(time.Now().Add(5 * time.Minute))
//
//	c, err := smtp.NewClient(conn, server)
//	if err != nil {
//		return err
//	}
//
//	if err := c.Hello(strings.TrimRight(name[0], ".")); err != nil {
//		return err
//	}
//
//	if err := c.Mail(msg.mailFrom); err != nil {
//		return err
//	}
//
//	if err := c.Rcpt(msg.rcptTo); err != nil {
//		return err
//	}
//
//	w, err := c.Data()
//	if err != nil {
//		return err
//	}
//
//	_, err = fmt.Fprint(w, msg.data)
//	if err != nil {
//		return err
//	}
//
//	err = w.Close()
//	if err != nil {
//		return err
//	}
//
//	return c.Quit()
//
//}
