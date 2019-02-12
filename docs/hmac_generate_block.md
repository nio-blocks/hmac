HMACgenerate
=======
Generate a one-way, unique hash for a **Message** using a **Key** from which the original message and key cannot be deciphered. This is useful for verifying the origin and contents of a message.

Three algorithms are available, and the **Key** used for each should be the same number of bytes as the resulting hash. So the key for MD5 should be 16 characters, SHA1 should be 20, and SHA256 32. You can use keys of any length, but values shorter than those given will be zero-padded, and longer keys truncated.

Properties
----------
**Key**: Secret key used to hash a message.
**Message**: Message to be hashed.
**Algorithm** (advanced): Hashing algorithm to use.
**Output Attribute** (advanced):

Example
-------
The simplest use of this block is to add a hash checksum to a message:

```
Key: foobarbaz
Message: {{ $message }}
Hashing Algorithm: MD5
Exclude Existing: False
```
<table width=100%>
<tr>
<th>Incoming Signals</th>
<th>Outgoing Signals</th>
</tr>
<tr>
<td>
<pre>
[
  {
    "message": "This is the song that never ends."
  }
]
</pre>
</td>
<td>
<pre>
[
  {
    "message": "This is the song that never ends.",
    "hash": "48f18105bf00e018462ba75e794e5b7e"
  }
]
</pre>
</td>
</tr>
</table>

Person A sends a message and its hash to Person B who shares the secret key. Person B hashes the received message with their key and compares it to the received hash. If equal, the message's contents have not been altered and can only have originated from someone with the secret key.

Commands
--------
None
