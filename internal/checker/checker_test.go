package checker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// directDial 在测试里充当“经代理”的拨号器。
func directDial(ctx context.Context, target string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", target)
}

func TestCheckIPAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","country":"United States","regionName":"Texas","city":"Houston","isp":"Acme Telecom","query":"203.0.113.44"}`))
	}))
	defer srv.Close()

	info, err := Check(context.Background(), directDial,
		[]Endpoint{{Name: "test", URL: srv.URL, Parse: parseIPAPI}}, 5*time.Second)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if info.IP != "203.0.113.44" || info.Region != "Texas" || info.City != "Houston" {
		t.Fatalf("解析结果不对: %+v", info)
	}
	if info.Source != "test" || info.CheckedAt.IsZero() {
		t.Errorf("来源/时间未填充: %+v", info)
	}
	if got, want := info.Label(), "203.0.113.44 · Texas, Houston"; got != want {
		t.Errorf("Label() = %q, want %q", got, want)
	}
	if !info.InRegion("texas") || !info.InRegion("Texas") {
		t.Error("InRegion 应匹配 Texas")
	}
	if info.InRegion("California") {
		t.Error("InRegion 不应匹配 California")
	}
}

func TestCheckIPInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ip":"198.51.100.7","city":"Dallas","region":"Texas","country":"US","org":"AS64500 Example"}`))
	}))
	defer srv.Close()

	info, err := Check(context.Background(), directDial,
		[]Endpoint{{Name: "ipinfo", URL: srv.URL, Parse: parseIPInfo}}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if info.IP != "198.51.100.7" || info.City != "Dallas" || info.ISP != "AS64500 Example" {
		t.Fatalf("解析结果不对: %+v", info)
	}
}

func TestCheckFallsBackToSecondEndpoint(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ip":"203.0.113.9","region":"Texas"}`))
	}))
	defer good.Close()

	info, err := Check(context.Background(), directDial, []Endpoint{
		{Name: "bad", URL: bad.URL, Parse: parseIPInfo},
		{Name: "good", URL: good.URL, Parse: parseIPInfo},
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("应回退到第二个接口: %v", err)
	}
	if info.Source != "good" {
		t.Errorf("来源应为 good，实际 %q", info.Source)
	}
}

func TestCheckAllEndpointsFail(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer bad.Close()

	_, err := Check(context.Background(), directDial,
		[]Endpoint{{Name: "bad", URL: bad.URL, Parse: parseIPInfo}}, 2*time.Second)
	if !errors.Is(err, ErrAllEndpointsFailed) {
		t.Fatalf("期望 ErrAllEndpointsFailed，实际 %v", err)
	}
}

func TestCheckUsesProvidedDialer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ip":"203.0.113.1"}`))
	}))
	defer srv.Close()

	used := false
	dial := func(ctx context.Context, target string) (net.Conn, error) {
		used = true
		return directDial(ctx, target)
	}
	if _, err := Check(context.Background(), dial,
		[]Endpoint{{Name: "t", URL: srv.URL, Parse: parseIPInfo}}, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Error("未使用传入的代理 Dialer —— 探测流量必须经代理，否则暴露真实 IP")
	}
}

func TestCheckRejectsNilDialer(t *testing.T) {
	if _, err := Check(context.Background(), nil, nil, time.Second); err == nil {
		t.Fatal("dial 为 nil 时应报错，绝不能退化为直连")
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := parseIPAPI([]byte(`{"status":"fail","message":"private range"}`)); err == nil {
		t.Error("status=fail 应报错")
	}
	if _, err := parseIPAPI([]byte(`not json`)); err == nil {
		t.Error("非 JSON 应报错")
	}
	if _, err := parseIPAPI([]byte(`{"status":"success"}`)); err == nil {
		t.Error("缺少 IP 应报错")
	}
	if _, err := parseIPInfo([]byte(`{}`)); err == nil {
		t.Error("缺少 IP 应报错")
	}
}

func TestLabelFallbacks(t *testing.T) {
	var nilInfo *ExitInfo
	if got := nilInfo.Label(); got != "出口未知" {
		t.Errorf("nil 的 Label() = %q", got)
	}
	if got := (&ExitInfo{}).Label(); got != "出口未知" {
		t.Errorf("空 IP 的 Label() = %q", got)
	}
	if got := (&ExitInfo{IP: "1.2.3.4"}).Label(); got != "1.2.3.4" {
		t.Errorf("只有 IP 时 Label() = %q", got)
	}
	if got := (&ExitInfo{IP: "1.2.3.4", Country: "US"}).Label(); got != "1.2.3.4 · US" {
		t.Errorf("只有国家时 Label() = %q", got)
	}
	if nilInfo.InRegion("Texas") {
		t.Error("nil 的 InRegion 应为 false")
	}
}
