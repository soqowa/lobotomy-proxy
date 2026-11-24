package main

import (
	"bufio"
	"bytes"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const checkHost = "route.proxyguard.test"

// No third-party assets and no JavaScript network access. The browser's time zone stays on the page.
var checkPage = template.Must(template.New("check").Parse(`<!doctype html>
<html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Проверка браузера · Proxy Guard</title>
<style>:root{color-scheme:light dark}body{font:16px/1.5 -apple-system,system-ui,sans-serif;max-width:36rem;margin:12vh auto;padding:0 24px}h1{font-size:30px}dt{color:#777;margin-top:18px}dd{font-weight:600;margin:3px 0}small{display:block;margin-top:28px}</style>
<h1>Проверка браузера</h1><dl><dt>Маршрут этого запроса</dt><dd>{{.Route}}</dd>
<dt>Часовой пояс выхода при установке</dt><dd id="expected">{{.Zone}}</dd>
<dt>Часовой пояс, который передаёт браузер</dt><dd id="observed">JavaScript выключен</dd></dl>
<p id="result"></p><small>Страница загружена с этого Mac. Проверка относится к этому окну и этому адресу.</small>
<script>const z=Intl.DateTimeFormat().resolvedOptions().timeZone;document.getElementById('observed').textContent=z;document.getElementById('result').textContent=z===document.getElementById('expected').textContent?'Часовые пояса совпадают.':'Часовые пояса различаются.';</script></html>`))

func diagnostic(c net.Conn, raw []byte, route string) bool {
	req, e := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if e != nil || req.Method != "GET" {
		return false
	}
	if !strings.EqualFold(req.Host, checkHost+":17688") || req.URL.Path != "/check" {
		return false
	}
	s, e := loadInstall()
	if e != nil {
		return false
	}
	var html bytes.Buffer
	_ = checkPage.Execute(&html, struct{ Route, Zone string }{route, s.Zone})
	fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\nContent-Length: %d\r\n\r\n", html.Len())
	_, _ = c.Write(html.Bytes())
	return true
}
func header(c net.Conn) []byte {
	var data []byte
	var one [1]byte
	for len(data) < 8192 {
		if _, e := io.ReadFull(c, one[:]); e != nil {
			return nil
		}
		data = append(data, one[0])
		if bytes.HasSuffix(data, []byte("\r\n\r\n")) {
			return data
		}
	}
	return nil
}
func localCheck(c net.Conn) {
	c.SetDeadline(time.Now().Add(4 * time.Second))
	diagnostic(c, header(c), "Системный DNS → локальная служба")
}
