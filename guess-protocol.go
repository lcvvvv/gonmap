package gonmap

func GuessProtocol(port int) string {
	protocol := NMAP_SERVICES_SLICE[port]
	if protocol == "unknown" {
		protocol = "http"
	}
	return protocol
}

func FixProtocol(oldProtocol string, port int) string {
	//进行最后输出修饰
	if oldProtocol == "ssl/http" {
		return "https"
	}
	if oldProtocol == "ssl/https" {
		return "https"
	}
	if oldProtocol == "ms-wbt-server" {
		return "rdp"
	}
	if oldProtocol == "microsoft-ds" {
		return "smb"
	}
	if oldProtocol == "netbios-ssn" {
		return "netbios"
	}
	if oldProtocol == "oracle-tns" {
		return "oracle"
	}
	if oldProtocol == "msrpc" {
		return "rpc"
	}
	if oldProtocol == "ms-sql-s" {
		return "mssql"
	}
	if oldProtocol == "domain" {
		return "dns"
	}
	if oldProtocol == "svnserve" {
		return "svn"
	}
	if oldProtocol == "ssl" && port == 3389 {
		return "rdp"
	}
	return oldProtocol
}
