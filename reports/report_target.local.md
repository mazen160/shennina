
# Shennina Exploitation Report

## Target: `target.local`

#### The target has been compromised using the following:


## Exploit: `exploit/linux/postgres/postgres_payload`

## Exploit Details

### Name

```
PostgreSQL for Linux Payload Execution
```

### Description

```
On some default Linux installations of PostgreSQL, the postgres service account may write to the /tmp directory, and may source UDF Shared Libraries from there as well, allowing execution of arbitrary code. This module compiles a Linux shared object file, uploads it to the target host via the UPDATE pg_largeobject method of binary injection, and creates a UDF (user defined function) from that shared object. Because the payload is run as the shared object's constructor, it does not need to conform to specific Postgres API versions.
```

### References

```
CVE-2007-3280
http://www.leidecker.info/pgshell/Having_Fun_With_PostgreSQL.txt
```

## Shell Type: `meterpreter`

## Payload: `payload/linux/x86/meterpreter/bind_ipv6_tcp`


