rule dirtjumper_drive3
{
 meta:
   author = "Jason Jones"
   author_email = "jasonjones@arbor.net"
   date = "2014-03-17"
   description = "Identify version of Drive DDoS malware using compromised sites"
  strings:
    $cmd1 = "-get" fullword
    $cmd2 = "-ip" fullword
    $cmd3 = "-ip2" fullword
    $cmd4 = "-post1" fullword
    $cmd5 = "-post2" fullword
    $cmd6 = "-udp" fullword
    $str1 = "login=[1000]&pass=[1000]&password=[50]&log=[50]&passwrd=[50]&user=[50]&username=[50]&vb_login_username=[50]&vb_login_md5password=[50]"
    $str2 = "-timeout" fullword
    $str3 = "-thread" fullword
    $str4 = " Local; ru) Presto/2.10.289 Version/"
    $str5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT"
    $newver1 = "-icmp"
    $newver2 = "-byte"
    $newver3 = "-long"
    $drive3 = "99=1"
  condition:
    4 of ($cmd*) and all of ($str*) and all of ($newver*) and $drive3
}
