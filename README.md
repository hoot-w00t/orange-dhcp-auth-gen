# DHCP authentication option generator

This script was made thanks to the reverse engineering work of [LaFibre.info](https://lafibre.info) members (https://lafibre.info/remplacer-livebox/cacking-nouveau-systeme-de-generation-de-loption-90-dhcp/).

## Usage
```
python3 orange-dhcp-auth-gen.py username [password]
```

The `fti/` prefix of the username is optional.
`password` is optional, you will be prompted for it later if it is omitted.

Password salts are randomly generated and can be dumped with `--verbose`.

The authentication option is printed as hexadecimal with each byte separated by `:`, you can change this separator with `--separator` or remove it with `--separator ""`.
