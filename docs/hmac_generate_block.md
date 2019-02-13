HMACgenerate
=======
Generate a one-way, unique hash for a **Message** using a **Key** from which the original message and key cannot be deciphered. This is useful for verifying the origin and contents of a message.

The **Key** used should be the same number of bytes as the resulting hash. Use the following table to determine the proper length for the algorithm used. You can use keys of any length, but values shorter than those given will be zero-padded, and longer keys truncated.

<table>
<tr>
<th>Hashing Algorithm</th>
<th>Key Length</th>
</tr>
<tr>
<td>MD5</td>
<td>16</td>
</tr>
<tr>
<td>SHA1</td>
<td>20</td>
</tr>
<tr>
<td>SHA256</td>
<td>32</td>
</tr>
<tr>
<td>SHA384</td>
<td>48</td>
</tr>
<tr>
<td>SHA512</td>
<td>64</td>
</tr>
</table>

Properties
----------
- **Key**: Secret key used to hash a message, must be `bytes`, `bytearray`, or `string`. If a `string` is used it will be encoded using `UTF-8`
- **Message**: Message to be hashed, must be `bytes`, `bytearray`, or `string`. If a `string` is used it will be encoded using `UTF-8`
- **Hashing Algorithm** (advanced): Hashing algorithm to use.
- **Binary Output** (advanced): Output hash bytes instead of the standard hex string.
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
