# cipher

An utility made in pure Go without any external dependencies, it uses symmetric encryption to encrypt or decrypt any txt files in the same directory using the password provided.
Can be used for simple things like making a digital diary unusable by most people.

## Installation

1. Install [Go](https://go.dev/) 1.20 or above.
2. Clone this repository with `git clone <repourl>`.
3. (Optional) Open `main.go` and change the salt in line 18 to something else random ([why](#why-change-salt)).
4. Run the build command:

```bash
go build .
```

## Usage

```bash
# windows
cipher.exe

# linux/etc
./cipher
```

## Why change salt

By changing the salt, you're basically adding an extra layer of protection to the encryption process. The salt acts as a random value that gets combined with the password to create a unique encryption key. This unique key makes it way more challenging for potential attackers to crack the encrypted files.

## License

This project is licensed under MIT, check it out [here](LICENSE)
