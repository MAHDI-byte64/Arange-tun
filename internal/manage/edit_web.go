package manage

import (
	"fmt"
	"net"
	"strings"

	"github.com/mahdi-byte64/arange-tun/internal/app"
	"github.com/mahdi-byte64/arange-tun/internal/optimize"
)

// Web edit path. TunnelForEdit reads a tunnel's on-disk config back into a
// TunnelRequest so the panel can prefill the same form it creates from, and
// UpdateTunnel writes the edited request over the existing tunnel and restarts
// it — so editing is one save instead of delete-and-recreate.

// TunnelForEdit loads a tunnel's config and maps it to the TunnelRequest shape
// the create form uses. Advanced tuning is included only when the tunnel is
// actually custom (no preset) or carries explicit limits, so a plain preset
// tunnel round-trips as a preset tunnel rather than being marked custom.
func TunnelForEdit(name string) (TunnelRequest, error) {
	cfg, err := LoadTunnelConfig(name)
	if err != nil {
		return TunnelRequest{}, err
	}
	req := TunnelRequest{Name: name}

	switch {
	case cfg.Server.BindAddr != "":
		s := cfg.Server
		req.Role = "server"
		req.Transport = string(s.Transport)
		req.Preset = s.Preset
		req.Token = s.Token
		if host, port, err := net.SplitHostPort(s.BindAddr); err == nil {
			req.Port = port
			req.IPv6 = host == "::"
		}
		req.Ports = s.Ports
		req.ProxyProtocol = s.ProxyProtocol
		req.SimpleAuth = s.SimpleAuth

		// TLS mode: ACME wins; a certificate under the auto-generated cert
		// directory is our self-signed one; anything else is a supplied pair.
		if needsTLS(string(s.Transport)) {
			switch {
			case s.ACMEDomain != "":
				req.TLSMode = "acme"
				req.ACMEDomain = s.ACMEDomain
				req.ACMEEmail = s.ACMEEmail
			case s.TLSCertFile != "" && !strings.HasPrefix(s.TLSCertFile, certDir+"/"):
				req.TLSMode = "existing"
				req.TLSCert = s.TLSCertFile
				req.TLSKey = s.TLSKeyFile
			default:
				req.TLSMode = "self"
			}
		}

		if s.Preset == "" || s.MaxConnections > 0 || s.BandwidthMbps > 0 {
			nd, au, zc := s.Nodelay, s.AcceptUDP, s.ZeroCopy
			req.Advanced = &AdvancedTuning{
				Nodelay:         &nd,
				KeepAlive:       s.Keepalive,
				Heartbeat:       s.Heartbeat,
				LogLevel:        s.LogLevel,
				LogFormat:       s.LogFormat,
				ChannelSize:     s.ChannelSize,
				AcceptUDP:       &au,
				MuxCon:          s.MuxCon,
				MuxVersion:      s.MuxVersion,
				MuxFrameSize:    s.MaxFrameSize,
				MuxRecvBuffer:   s.MaxReceiveBuffer,
				MuxStreamBuffer: s.MaxStreamBuffer,
				KCPMTU:          s.MTU,
				KCPInterval:     s.Interval,
				KCPSndWnd:       s.SndWnd,
				KCPRcvWnd:       s.RcvWnd,
				KCPDataShards:   s.DataShards,
				KCPParityShards: s.ParityShards,
				MaxConnections:  s.MaxConnections,
				BandwidthMbps:   s.BandwidthMbps,
				ZeroCopy:        &zc,
			}
		}

	case cfg.Client.RemoteAddr != "":
		c := cfg.Client
		req.Role = "client"
		req.Transport = string(c.Transport)
		req.Preset = c.Preset
		req.Token = c.Token
		if host, port, err := net.SplitHostPort(c.RemoteAddr); err == nil {
			req.ServerHost = host
			req.ServerPort = port
		}
		req.EdgeIP = c.EdgeIP
		req.Proxy = c.Proxy
		req.Interface = c.Interface
		req.LocalAddr = c.LocalAddr
		req.FallbackAddrs = c.FallbackAddrs
		req.LoadBalance = c.LoadBalance
		req.SimpleAuth = c.SimpleAuth

		if c.Preset == "" {
			nd, ap, zc := c.Nodelay, c.AggressivePool, c.ZeroCopy
			req.Advanced = &AdvancedTuning{
				Nodelay:         &nd,
				KeepAlive:       c.Keepalive,
				LogLevel:        c.LogLevel,
				LogFormat:       c.LogFormat,
				ConnectionPool:  c.ConnectionPool,
				AggressivePool:  &ap,
				MuxCon:          c.MuxSession,
				MuxVersion:      c.MuxVersion,
				MuxFrameSize:    c.MaxFrameSize,
				MuxRecvBuffer:   c.MaxReceiveBuffer,
				MuxStreamBuffer: c.MaxStreamBuffer,
				KCPMTU:          c.MTU,
				KCPInterval:     c.Interval,
				KCPSndWnd:       c.SndWnd,
				KCPRcvWnd:       c.RcvWnd,
				KCPDataShards:   c.DataShards,
				KCPParityShards: c.ParityShards,
				ZeroCopy:        &zc,
			}
		}

	default:
		return TunnelRequest{}, fmt.Errorf("tunnel %q has neither a server nor a client section", name)
	}

	return req, nil
}

// UpdateTunnel rewrites an existing tunnel from an edited request and restarts
// it so the change takes effect. It is CreateTunnel for a name that already
// exists: same validation and building, but it requires the tunnel to be there
// rather than refusing because it is.
func UpdateTunnel(req TunnelRequest) (CreateResult, error) {
	name := strings.TrimSpace(req.Name)
	if !fileExists(app.ConfigPath(name)) {
		return CreateResult{}, fmt.Errorf("no tunnel named %q to edit", name)
	}
	spec, err := buildSpec(req)
	if err != nil {
		return CreateResult{}, err
	}

	optimize.ApplyQuiet()

	service, err := spec.Save()
	if err != nil {
		return CreateResult{}, err
	}
	// Save (re)starts the service, but a service that was already running keeps
	// the old config until it is restarted, so make the edit take effect.
	if err := RestartService(service); err != nil {
		return CreateResult{Name: spec.Name, Service: service, Active: IsActive(service), Token: spec.Token}, err
	}
	return CreateResult{
		Name:    spec.Name,
		Service: service,
		Active:  IsActive(service),
		Token:   spec.Token,
	}, nil
}
