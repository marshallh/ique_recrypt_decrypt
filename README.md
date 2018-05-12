# ique_recypt_decrypt

ique_recrypt_decrypt 0.1 by marshallh
-------------------------------------
Arguments: ique_recrypt_decrypt
         -otp <otp.bin>
         -rec <recrypt.sys from same console>
         -recout <decrypted rec output>

For each recrypted title slot in the file details will be printed.


# Sample output

ique_recrypt_decrypt 0.1 by marshallh
-------------------------------------
* Opening OTP binary otp_bbid_3C66.bin
- OTP was dumped from a console with BBID of 00003C66
* Opening REC binary recrypt.sys
* Opening RECout binary recrypt_dec.sys
* Found 4 recrypt entries in this file
* Entry 0:
  Content ID   : 4101105 (0x003E93F1)
  Content name : Star Fox 64
  Content key  : 2B9A184F55FB62F64267896596C1F31E
* Entry 1:
  Content ID   : 6101104 (0x005D1870)
  Content name : Dr. Mario 64
  Content key  : 833258A122C95EFE8A210C4073F11C6E
* Entry 2:
  Content ID   : 1101104 (0x0010CD30)
  Content name : Super Mario 64
  Content key  : CBC48C383EC418F972C68B0CACD12D30
* Entry 3:
  Content ID   : 2101104 (0x00200F70)
  Content name : The Legend of Zelda: Ocarina of Time
  Content key  : 4882BAE90A06A4AA1B858AB06B11C4DC
* Done