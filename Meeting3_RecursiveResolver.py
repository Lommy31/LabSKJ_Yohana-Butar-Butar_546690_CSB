import dns.message
import dns.query
import dns.rdatatype
import dns.exception

# Root server list (pakai satu untuk awal, bisa ditambah)
ROOT_SERVERS = [
    "198.41.0.4",   # a.root-servers.net
    "199.9.14.201", # b.root-servers.net
    "192.33.4.12",  # c.root-servers.net
]

def query_dns(domain, server, qtype=dns.rdatatype.A):
    """
    Kirim query DNS ke server tertentu
    """
    try:
        q = dns.message.make_query(domain, qtype)
        r = dns.query.udp(q, server, timeout=3)
        return r
    except dns.exception.Timeout:
        print(f"[!] Timeout querying {server}")
        return None
    except Exception as e:
        print(f"[!] Error querying {server}: {e}")
        return None

def recursive_resolve(domain, server_ip, hops=None):
    """
    Resolver rekursif sederhana.
    """
    if hops is None:
        hops = []

    hops.append(server_ip)
    print(f"[*] Querying {domain} at {server_ip}")

    resp = query_dns(domain, server_ip)
    if resp is None:
        return None, hops

    # 1. Cek ANSWER section
    for ans in resp.answer:
        for item in ans:
            if item.rdtype == dns.rdatatype.A:
                print(f"[+] Final Answer from {server_ip}: {item.address}")
                return item.address, hops
            elif item.rdtype == dns.rdatatype.CNAME:
                cname = str(item.target)
                print(f"[~] CNAME found: {cname}")
                return recursive_resolve(cname, ROOT_SERVERS[0], hops)

    # 2. Cek ADDITIONAL section → ambil IP NS langsung
    for add in resp.additional:
        for item in add:
            if item.rdtype == dns.rdatatype.A:
                return recursive_resolve(domain, item.address, hops)

    # 3. Cek AUTHORITY section → ada NS name
    for auth in resp.authority:
        for item in auth:
            if item.rdtype == dns.rdatatype.NS:
                ns_name = str(item.target)
                print(f"[>] Need to resolve NS hostname: {ns_name}")
                # Resolve hostname NS pakai root server lagi
                ns_ip, _ = recursive_resolve(ns_name, ROOT_SERVERS[0])
                if ns_ip:
                    return recursive_resolve(domain, ns_ip, hops)

    # Kalau sampai sini, gagal resolve
    print(f"[!] Failed to resolve {domain} at {server_ip}")
    return None, hops


if __name__ == "__main__":
    domain = "www.example.com"
    final_ip, hop_sequence = recursive_resolve(domain, ROOT_SERVERS[0])

    print("\n=== Result ===")
    if final_ip:
        print(f"Domain {domain} resolved to: {final_ip}")
    else:
        print(f"Failed to resolve {domain}")

    print("\nHop sequence:")
    for i, hop in enumerate(hop_sequence, 1):
        print(f"{i}. {hop}")
