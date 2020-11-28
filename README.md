# kerberos

This repo contains educational code I created to better undertand Kerberos. The repo now only includes code to use a Kerberoasting attack, but I might add new Kerberos attacks in the future.

# How to use

First search for an SPN you want to Kerberoast:  
```setspn Q */*```

Once you've found an SPN, use it as a parameter to get the TGS hash:  
```Kerberos.exe MSSQLSERVER/SQL-Server.thalpius.demo:1433```
