Wedge Importer
==============

The importer tool. Only tested for importing SMF 2.0 data into Wedge.

How to import from SMF, then?
-----------------------------

Wedge is currently in alpha. This means it's not recommended to use it on a production website.

I don't care! I'm craaaaazy! What then uh?
------------------------------------------

Please don't hurt me.

First, install Wedge:

- Go to http://github.com/Wedge/wedge/
- Download ZIP
- Unzip, FTP the contents to your server.
- Go to your forum root with your browser. If you don't see anything, visit `mysite.com/myforum/index.php` specifically.
- Follow the instructions.

Then, install the importer:

- From this repository, click Download ZIP
- Unzip, FTP the contents to your server.
- The contents must be in the forum root, just like install.php was.
- Point your browser to the `import.php` path. (`mysite.com/myforum/import.php`)
- Follow the instructions.
- Done! You now have two working forums: a SMF 2.0 forum, and a version of it running Wedge.

Please note that currently, Aeva Media galleries are NOT imported.
Also, attachments aren't imported if they're located in custom attachment folders.
This should hopefully be fixed in the future.
