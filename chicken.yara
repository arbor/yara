rule chicken_dos{
  meta:
    author = "Jason Jones <jasonjones@arbor.net>"
    description= "Win32-variant of Chicken ident for both dropper and dropped file"
  strings:
    $pdb1 = "\\Chicken\\Release\\svchost.pdb"
    $pdb2 = "\\IntergrateCHK\\Release\\IntergrateCHK.pdb"
    $str2 = "fake.cf"
    $str3 = "8.8.8.8"
    $str4 = "Processor(%d)\\"
    $str5 = "DbProtectSupport"
    $str1 = "dm1712/`jvpnpkte/bpl"
    $str6 = "InstallService NPF %d"
    $str7 = "68961"
    $str8 = "InstallService DbProtectSupport %d"
    $str9 = "C:\\Program Files\\DbProtectSupport\\npf.sys"
  condition:
    ($pdb1 or $pdb2) and 5 of ($str*)
}
