HMACgenerate
=======
Generate a one-way, unique hash for a **Message** using a **Key** from which the original message and key cannot be deciphered. This is useful for verifying the origin and contents of a message.

Three algorithms are available, and the **Key** used for each should be the same number of bytes as the resulting hash. So the key for MD5 should be 16 characters, SHA1 should be 20, and SHA256 32. You can use keys of any length, but values shorter than those given will be zero-padded, and longer keys truncated.

Properties
----------
- **Key**: Secret key used to hash a message, must be `bytes`, `bytearray`, or `string`. If a `string` is used it will be encoded using `UTF-8`
- **Message**: Message to be hashed, must be `bytes`, `bytearray`, or `string`. If a `string` is used it will be encoded using `UTF-8`
- **Algorithm** (advanced): Hashing algorithm to use.
- **Output Attribute** (advanced): Signal attribute to contain the hash, default `hash`

Example
-------
The simplest use of this block is to add a hash checksum to a message:

```
Key: foobarbaz
Message: {{ $message }}
Hashing Algorithm: SHA256
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
    "hash": "ca03e75cd1116e5fa9a1b4cec26cb11d59d98db90a8ff185219af4537af7c2ec"
  }
]
</pre>
</td>
</tr>
</table>

Person A sends a message and its hash to Person B who shares the secret key. Person B generates a hash for the received message with their key and compares it to the received hash. If equal, the message's contents have not been altered and can only have originated from someone with the secret key.

Commands
--------
None
