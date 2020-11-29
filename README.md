# Kerberoasting

I have created a small C# project that requests a Ticket Granting Service ticket using KerberosSecurityTokenProvider to use for Kerberoasting. I started the project for educational purposes only, but the tool works fine and is not detected by Microsoft Defender for Identity.

# How to use

First search for an SPN you want to Kerberoast:  
```setspn -Q */*```

Once you've found an SPN, use it as a parameter to get the TGS hash which you can use to crack:  
```Kerberoasting.exe MSSQLSERVER/SQL-Server.thalpius.demo:1433```

# Screenshots

Getting all Service Principal Names within the domain:
![Alt text](/Screenshots/Kerberoasting_01.jpg?raw=true "Get SPNs")

Using Kerberoasting.exe to get the Ticket Granting Service ticket to Kerberoast:
![Alt text](/Screenshots/Kerberoasting_02.jpg?raw=true "Get TGS")
