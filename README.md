# robloxshellcode

a way of forcing roblox to execute your shellcode by abusing thread pools :p

<br><br>
too lazy to turn it into a manualmapper but it is not hard to do so

<br><br>
note that: hyperion will periodically scan Roblox's entire process memory (along with allocated memory) <br>
and it will strip the X flag from the shellcode, the X flag will also be stripped whenever a syscall is <br>
invoked, as hyperion's IC will intercept it
<br><br>
this is not hard to circumvent, but this does not account for that

<br><sup>this is probs more dtc than CryptSIPVerifyIndirectData\WinVerifyTrust "bypass"</sup>   <img src="https://em-content.zobj.net/content/2020/07/27/cry.png" alt="cry" width="20" height="20">
