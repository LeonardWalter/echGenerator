# Go ECH Key Generator

This Go project generates Encrypted ClientHello (ECH) key and configuration PEM files according to https://datatracker.ietf.org/doc/draft-farrell-tls-pemesni/

## Installation

1.  Clone the repository:

    ```bash
    git clone https://github.com/LeonardWalter/echGenerator.git
    cd echGenerator
    ```

2.  Build the executable:

    ```bash
    go build
    ./echGenerator -s example.com -i 123 -o mykeys.pem
    ```

## Usage

```bash
-s: Server name (required).
-i: ECH ID (uint8). If not provided, a random ID will be generated.
-o: Output file name. If not provided, the output file will be <server_name>.pem.ech
-h: Show help.
```

## Example output:
 ```pem
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIG7Wc0oeswNKlNMfNe+gSwaFhVU3GDdoSAzfZGDpSaIm
-----END PRIVATE KEY-----
-----BEGIN ECHCONFIG-----
AEb+DQBCFQAgACAfYnXA4GJHffFuchf/+AMUNodczfzPy8RLtVOjFs7FZwAMAAEAAQABAAIAAQADIAtleGFtcGxlLmNvbQAA
-----END ECHCONFIG-----
 ```
