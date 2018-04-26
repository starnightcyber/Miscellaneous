# Horde

## CVE-2017-16906

### Description

	In Horde Groupware 5.2.19, there is XSS via the URL field in a "Calendar -> New Event" action.

But this vulnerability still exists in Horde Groupware 5.2.22.

Calendar -> New Event -> Set URL field to

	http://localhost/">"><script>alert(/horde groupware 5.2.22 xss/)</script>
	
[image](https://raw.githubusercontent.com/starnightcyber/Miscellaneous/master/Horde/1.png)

Click the event we just created, XSS triggered.

[image](https://raw.githubusercontent.com/starnightcyber/Miscellaneous/master/Horde/2.png)