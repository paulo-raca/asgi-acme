def sorted_hostnames(hostnames: list[str]) -> list[str]:
    return sorted(hostnames, key=lambda hostname: list(reversed(hostname.split("."))))

if __name__ == "__main__":
    print(sort_hostnames(["foo.com", "www.foo.com", "foo.xyz", "bar.com", "foo.a", "a.com", "z.com"]))
