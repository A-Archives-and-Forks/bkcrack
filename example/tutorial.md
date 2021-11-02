Tutorial {#tutorial}
========

\brief A guide to crack an example encrypted zip file.

The `example` folder contains an example zip file `secrets.zip` so you can run an attack.
Its content is probably of great interest!

# What is inside

Let us see what is inside.
Open a terminal in the `example` folder and ask `unzip` to give us information about it.

    $ unzip -Z secrets.zip

We get the following output.

    Archive:  secrets.zip
    Zip file size: 56263 bytes, number of entries: 2
    -rw-rw-r--  6.3 unx    54799 Bx defN 12-Aug-14 14:51 advice.jpg
    -rw-rw-r--  6.3 unx     1265 Bx stor 18-Dec-20 13:33 spiral.svg
    2 files, 56064 bytes uncompressed, 55953 bytes compressed:  0.2%

The zip file contains two files: `advice.jpg` and `spiral.svg`.
The capital letter in the fifth field shows the files are encrypted.
We also see that `advice.jpg` is deflated whereas `spiral.svg` is stored uncompressed.

# Guessing plaintext

To run the attack, we must guess at least 12 bytes of plaintext.
On average, the more plaintext we guess, the faster the attack will be.

## The easy way: stored file

We can guess from its extension that `spiral.svg` probably starts with the string `<?xml version="1.0" `.

We are so lucky that this file is stored uncompressed in the zip file.
So we have 20 bytes of plaintext, which is more than enough.

## The not so easy way: deflated file

Let us assume the zip file did not contain the uncompressed `spiral.svg`.

Then, to guess some plaintext, we can guess the first bytes of the original `advice.jpg` file from its extension.
The problem is that this file is compressed.
To run the attack, one would have to guess how those first bytes are compressed, which is difficult without knowing the entire file.

In this example, this approach is not practical.
It can be practical if the original file can easily be found online, like a .dll file for example.
Then, one would compress it using various compression software and compression levels to try and generate the correct plaintext.

## Free additional byte from CRC

In this example, we guessed the first 20 bytes of `spiral.svg`.

In addition, as explained in the ZIP file format specification, a 12-byte encryption header in prepended to the data in the archive.
The last byte of the encryption header is the most significant byte of the file's CRC.

We can get the CRC with `unzip`.

    $ unzip -Z -v secrets.zip spiral.svg | grep CRC
      32-bit CRC value (hex):                         a99f1d0d

So we know the byte just before the plaintext (i.e. at offset -1) is 0xA9.

# Running the attack

Let us write the plaintext we guessed in a file.

    $ echo -n '<?xml version="1.0" ' > plain.txt

We are now ready to run the attack.

    $ ../bkcrack -C secrets.zip -c spiral.svg -p plain.txt -x -1 A9

After a little while, the keys will appear!

    [17:42:43] Z reduction using 13 bytes of known plaintext
    100.0 % (13 / 13)
    [17:42:44] Attack on 542303 Z values at index 6
    Keys: c4490e28 b414a23d 91404b31
    33.9 % (183761 / 542303)
    [17:48:03] Keys
    c4490e28 b414a23d 91404b31

# Recovering the original files

Once we have the keys, we can recover the original files.

## Choose a new password

We assume that the same keys were used for all the files in the zip file.
We can create a new encrypted archive based on `secret.zip`, but with a new password, `easy` in this example.

    $ ../bkcrack -C secrets.zip -k c4490e28 b414a23d 91404b31 -U secrets_with_new_password.zip easy

Then, any zip file utility can extract the created archive. You will just have to type the chosen password when prompted.

## Or decipher files

Alternatively, we can decipher files one by one.

    $ ../bkcrack -C secrets.zip -c spiral.svg -k c4490e28 b414a23d 91404b31 -d spiral_deciphered.svg

The file `spiral.svg` was stored uncompressed so we are done.

    $ ../bkcrack -C secrets.zip -c advice.jpg -k c4490e28 b414a23d 91404b31 -d advice_deciphered.deflate

The file `advice.jpg` was compressed with the deflate algorithm in the zip file, so we now have to uncompressed it.

A python script is provided for this purpose in the `tools` folder.

    $ python3 ../tools/inflate.py < advice_deciphered.deflate > very_good_advice.jpg

You can now open `very_good_advice.jpg` and enjoy it!

# Recovering the original password

As shown above, the original password is not required to decrypt data.
The internal keys are enough.
However, we might also be interested in finding the original password.
To do this, we need to choose a maximum length and a set of characters among which we hope to find those that constitute the password.
To save time, we have to choose those parameters wisely.
For a given maximal length, a small charset will be explored much faster than a big one, but making a wrong assumption by choosing a charset that is too small will not allow to recover the password.

At first, we can try all candidates up to a given length without making any assumption about the character set. We use the charset `?b` which is the set containing all bytes (from 0 to 255), so we not miss any candidate up to length 9.

    $ ../bkcrack -k c4490e28 b414a23d 91404b31 -r 9 ?b

    [17:52:16] Recovering password
    length 0
    length 1
    length 2
    length 3
    length 4
    length 5
    length 6
    length 7
    length 8
    length 9
    [17:52:16] Could not recover password

It failed so we know the password has 10 characters or more.

Now, let us assume the password is made of 11 or less printable ASCII characters, using the charset `?p`.

    $ ../bkcrack -k c4490e28 b414a23d 91404b31 -r 11 ?p

    [17:52:34] Recovering password
    length 0
    length 1
    length 2
    length 3
    length 4
    length 5
    length 6
    length 7
    length 8
    length 9
    length 10
    length 11
    100.0 % (9025 / 9025)
    [17:52:38] Could not recover password

It failed again so we know the password has non-printable ASCII characters or has 12 or more characters.

Now, let us assume the password is made of 12 or less alpha-numerical characters.

    $ ../bkcrack -k c4490e28 b414a23d 91404b31 -r 12 ?a

    [17:54:37] Recovering password
    length 0
    length 1
    length 2
    length 3
    length 4
    length 5
    length 6
    length 7
    length 8
    length 9
    length 10
    length 11
    length 12
    Password: W4sF0rgotten
    51.9 % (1996 / 3844)
    [17:54:49] Password
    as bytes: 57 34 73 46 30 72 67 6f 74 74 65 6e
    as text: W4sF0rgotten

Tada! We made the right assumption for this case.
The password was recovered quickly from the keys.
