import dns.resolver

# Use Google and Cloudflare public DNS instead of the system resolver.
# This avoids split-horizon DNS, ISP hijacking, and inconsistent local configs.
NAMESERVERS = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']


def make_resolver(timeout: float = 5, lifetime: float = 10) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = NAMESERVERS
    r.timeout = timeout
    r.lifetime = lifetime
    return r
