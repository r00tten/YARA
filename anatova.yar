rule anatova {

meta:
	author = "Mert Degirmenci"
	category = "ransomware"
	description = "YARA rule to detect ANATOVA ransomware"

strings:
	$magicByte = {4D 5A}
	$s_encrypttedSign = {5B DD 4B 14}
	$s_name = "ANATOVA" ascii wide nocase
	$s_mail1 = "anatova2@tutanota.com" ascii wide nocase
	$s_mail2 = "anatoday@tutanota.com" ascii wide nocase

condition:
	$magicByte at 0 and (all of ($s*))

}
