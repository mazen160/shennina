
# Shennina Exploitation Report

## Target: `192.168.43.216`

#### The target has been compromised using the following:


## Exploit: `exploit/multi/http/phptax_exec`

## Exploit Details

### Name

```
PhpTax pfilez Parameter Exec Remote Code Injection
```

### Description

```
This module exploits a vulnerability found in PhpTax, an income tax report generator. When generating a PDF, the icondrawpng() function in drawimage.php does not properly handle the pfilez parameter, which will be used in an exec() statement, and then results in arbitrary remote code execution under the context of the web server. Please note: authentication is not required to exploit this vulnerability.
```

### References

```
OSVDB-86992
EDB-21665
```

## Shell Type: `shell`

## Payload: `payload/cmd/unix/reverse`


