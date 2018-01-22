Function Get-ASN1ValueLength {
	<#
		.SYNOPSIS
			Gets the length of the value of the ASN.1 structure.

		.DESCRIPTION
			This cmdlet reads the length of the ASN.1 property. The BinaryReader input position should be
			on the byte directly after the tag value. After the cmdlet is executed, the reader is advanced
			the length of the bytes used to represent the value length and will be on the first byte of the
			value so it is prepared to read the value bytes next.

		.PARAMETER Reader
			The BinaryReader that is being used to read the byte stream containing the ASN1 structure

		.PARAMETER UseLongLengthFormat
			This switch indicates that the ASN.1 property uses a multi-byte length format, such as a Sequence or Octet String.

		.EXAMPLE
			$Content = Get-Content -Path c:\cert.pem -Raw
			$Bytes = [System.Convert]::FromBase64String($Content)
			[System.IO.MemoryStream]$MS = New-Object -TypeName System.IO.MemoryStream($Bytes)
			[System.IO.BinaryReader]$Reader = New-Object -TypeName System.IO.BinaryReader($MS)
			[System.Byte]$Tag = $Reader.ReadByte()
			[System.UInt32]$Length = Get-ASN1ValueLength -Reader $Reader
			[System.Byte[]]$Value = $Reader.GetBytes($Length)

			This example shows how to retrieve the length of the ASN.1 property indicated by the $Tag value. The cert.pem file contains
			only a base64 encoded string of a structure using the ASN.1 format.

		.INPUTS
			System.IO.BinaryReader

		.OUTPUTS
			System.UInt32

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 1/22/2018
	#>
	[CmdletBinding()]
	[OutputType([System.UInt32])]
    Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [System.IO.BinaryReader]$Reader,

        [Parameter()]
        [Switch]$UseLongLengthFormat
    )

    Begin {
    }

            Process {

                $LengthByte = $Reader.ReadByte()
                [System.UInt32]$LengthToReadNext = 0

                if ($UseLongLengthFormat)
                {
                    if (($LengthByte -band (1 -shl 7)) -ne 0)
                    {
                        # Shift left 4 to kick out the 4 high bits, then right 4
                        # to move the bits back to their original spot, would be same
                        # as doing a -band with 0x0F => 0000 1111
                        [System.UInt16]$MoreBytesToRead = ($LengthByte -shl 4) -shr 4
                    
                        [System.Byte[]]$LengthBytes = $Reader.ReadBytes($MoreBytesToRead)

                        $LengthBytes = Set-ByteArrayPadding -InputObject $LengthBytes -Length 4

                        if ([System.BitConverter]::IsLittleEndian)
                        {
                            [System.Array]::Reverse($LengthBytes)
                        }

                        $LengthToReadNext = [System.BitConverter]::ToUInt32($LengthBytes, 0)
                    }
                    else
                    {
                        $LengthToReadNext = [System.Convert]::ToUInt32($LengthByte)
                    }
                }
                else
                {
                    $LengthToReadNext = [System.Convert]::ToUInt32($LengthByte)
                }

                Write-Output -InputObject $LengthToReadNext
            }

            End {

            }
        }

Function Read-ASN1Content {
	<#
		.SYNOPSIS
			Reads the contents of an ASN.1 formatted data structure.

		.DESCRIPTION
			This cmdlet takes input from a file with base64 encoded content, a byte array, the base64 encoded string, or 
			a binary reader. It recursively reads through bytes and produces a hash table as output. Most ASN.1 formatted structures
			have a Sequence at the root of the structure, however it is not necessary for this parser. 

			The output format depends on the properties. Primitive types such as integer, boolean, and Unicode String are a hash table
			with a Tag, Data, and Length property. Constructed types such as Sequence or Set use a hashtable whose key values are the index
			number of the contained objects and the value of those keys are a hashtable with the object's properties. For example, if the top level
			item is a sequence and the sequence contains an integer and a boolean, the hash table would look like:

			@{
				"0" = {
					"Data" = 5;
					"Length = 1;
					"Tag" = 0x02
				},
				"1" = {
					"Data" = $false;
					"Length = 1;
					"Tag" = 0x01
				}
			}

		.PARAMETER Reader
			A binary reader whose current position is on a tag value for the ASN.1 structure.

		.PARAMETER Path
			The path to file containing ASN.1 data that is encoded as a base64 string.

		.PARAMETER Base64String
			A base64 string that contains the ASN.1 structure.

		.PARAMETER Content
			The byte content of the ASN.1 structure.

		.EXAMPLE
			$Content = Get-Content -Path c:\cert.pem -Raw
			$Bytes = [System.Convert]::FromBase64String($Content)
			[System.Collections.Hashtable]$Data = Read-ASN1Content -Content $Bytes

			This example reads the content of the cert.pem file (it doesn't have any non-base64 content in it) and parses
			the ASN.1 data structure into a hash table.

		.INPUTS
			System.IO.BinaryReader or System.Byte[]

		.OUTPUTS
			System.Collections.Hashtable

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 1/22/2018
	#>
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Reader", Position = 0)]
        [System.IO.BinaryReader]$Reader,

		[Parameter(Mandatory = $true, ParameterSetName = "Path")]
		[ValidateNotNullOrEmpty()]
		[System.String]$Path,

		[Parameter(Mandatory = $true, ParameterSetName = "Base64")]
		[ValidateNotNullOrEmpty()]
		[System.String]$Base64String,

		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Bytes", Position = 0)]
		[ValidateNotNullOrEmpty()]
		[System.Byte[]]$Content
    )

    Begin {
        # https://msdn.microsoft.com/en-us/library/windows/desktop/bb648640(v=vs.85).aspx
        # https://www.cryptologie.net/article/262/what-are-x509-certificates-rfc-asn1-der/
    }

    Process {
		switch ($PSCmdlet.ParameterSetName)
		{
			"Path" {
				$Content = [System.Convert]::FromBase64String((Get-Content -Path $Path -Raw).Replace("\n", "").Replace("\r", ""))
				[System.IO.MemoryStream]$MS = New-Object -TypeName System.IO.MemoryStream(,$Content)
				$Reader = New-Object -TypeName System.IO.BinaryReader($MS)
				break
			}
			"Bytes" {
				[System.IO.MemoryStream]$MS = New-Object -TypeName System.IO.MemoryStream(,$Content)
				$Reader = New-Object -TypeName System.IO.BinaryReader($MS)
				break
			}
			"Base64" {
				$Content = [System.Convert]::FromBase64String($Base64String.Replace("\n", "").Replace("\r", ""))
				[System.IO.MemoryStream]$MS = New-Object -TypeName System.IO.MemoryStream(,$Content)
				$Reader = New-Object -TypeName System.IO.BinaryReader($MS)
				break
			}
			"Reader" {
				# Do nothing
				break
			}
			default {
				Write-Error -Exception (New-Object -TypeName System.ArgumentException("Parameter set $($PSCmdlet.ParameterSetName) unknown for $($MyInvocation.MyCommand).")) -ErrorAction Stop
			}
		}

        $Result = @{}

        $Counter = 0

		# Wrap in the try so we can dispose of the BinaryReader at the end in a finally
		try
		{
			while ($Reader.BaseStream.Position -ne $Reader.BaseStream.Length)
			{
				# The TAG value
				[System.Byte]$Tag = $Reader.ReadByte()

				# Default to 0
				[System.UInt32]$LengthToReadNext = 0

				# Default 
				[System.Byte]$LengthByte = 0x00

				[System.Byte[]]$Bytes = @()
				$Data = $null
        
				# If the length of the sequence is more than 127 bytes
				# Bit 7 of the length field is set to 1, and bits 6 through 0 specify
				# the number of additional bytes use to identify the content length

                
				# This will take 1, i.e. 0x01 and shift it left 7 places, making it 0x80
				# Then we binary AND the length byte and 0x80, if both have the most significant
				# bit set, number 7, then the result would be 128, which is not equal to 0, otherwise
				# the result is 0 if the LengthByte does not have but number 7 set
				# Find the TAG for this item in the ASN.1 data
				switch ($Tag)
				{
					# Boolean
					0x01 {
						$LengthToReadNext = Get-ASN1ValueLength -Reader $Reader
                
						$Bytes = $Reader.ReadBytes($LengthToReadNext)
						$Data = [System.Convert]::ToBoolean($Bytes[0])

						break
					}
					# Int
					0x02 {
						$LengthToReadNext = Get-ASN1ValueLength -Reader $Reader -UseLongLengthFormat

						$Bytes = $Reader.ReadBytes($LengthToReadNext)

						$Bytes = Set-ByteArrayPadding $Bytes -Length 4

						if ([System.BitConverter]::IsLittleEndian)
						{
							[System.Array]::Reverse($Bytes)
						}

						$Data = [System.BitConverter]::ToUInt32($Bytes, 0)

						break
					}
					# Bit string
					# A bit or binary string is an arbitrarily long array of bits. Specific bits can be identified by parenthesized integers and assigned names
					0x03 {
						$LengthToReadNext = Get-ASN1ValueLength -Reader $Reader -UseLongLengthFormat

						$Bytes = $Reader.ReadBytes($LengthToReadNext)
                
						# Need to find best way to read bit string
						$Data = @{}

						break
					}
					# Octet stream
					# An octet string is an arbitrarily large byte array. Unlike the BIT STRING type, however, specific bits and bytes in the string cannot be assigned names.
					0x04 {
						$LengthToReadNext = Get-ASN1ValueLength -Reader $Reader -UseLongLengthFormat

						$Bytes = $Reader.ReadBytes($LengthToReadNext)

						$Data = @{}

						break
					}
					# NULL
					0x05 {
						$LengthToReadNext = $Reader.ReadByte() # This will be 0x00
                
						$Bytes = @()
						$Data = $null

						break
					}
					# Object Identifier
					0x06 {
						$LengthToReadNext = Get-ASN1ValueLength -Reader $Reader

						$Bytes = $Reader.ReadBytes($LengthToReadNext)

						$Data = ConvertTo-OIDString -InputObject $Bytes

						break
					}
					# UTF8 String
					0x0C {
						$LengthToReadNext = Get-ASN1ValueLength -Reader $Reader -UseLongLengthFormat

						$Bytes = $Reader.ReadBytes($LengthToReadNext)

						$Data = [System.Text.Encoding]::UTF8.GetString($Bytes)

						break
					}
					# Numeric String
					0x12 {
						$LengthToReadNext = Get-ASN1ValueLength -Reader $Reader -UseLongLengthFormat

						$Bytes = $Reader.ReadBytes($LengthToReadNext)

						$Data =  [System.Text.Encoding]::ASCII.GetString($Bytes)

						break
					}
					# Printable String
					# The PrintableString data type was originally intended to represent the limited character sets available to mainframe input terminals, but it is still commonly used. It contains the following characters:
					# A-Z
					# a-z
					# 0-9
					# ' ( ) + , - . / : = ? [space]
					0x13 {
						$LengthToReadNext = Get-ASN1ValueLength -Reader $Reader -UseLongLengthFormat

						$Bytes = $Reader.ReadBytes($LengthToReadNext)

						$Data =  [System.Text.Encoding]::ASCII.GetString($Bytes)

						break
					}
					# T61String / Teletex String
					0x14 {
						$LengthToReadNext = Get-ASN1ValueLength -Reader $Reader -UseLongLengthFormat

						$Bytes = $Reader.ReadBytes($LengthToReadNext)

						$Data =  [System.Text.Encoding]::ASCII.GetString($Bytes)

						break
					}
					# IA5String
					# The International Alphabet number 5 (IA5) is generally equivalent to the ASCII alphabet, 
					# but different versions can include accents or other characters specific to a regional language.
					0x16 {
						$LengthToReadNext = Get-ASN1ValueLength -Reader $Reader -UseLongLengthFormat

						$Bytes = $Reader.ReadBytes($LengthToReadNext)

						$Data =  [System.Text.Encoding]::ASCII.GetString($Bytes)

						break
					}
					# UTCTime
					0x17 {
						$LengthToReadNext = Get-ASN1ValueLength -Reader $Reader -UseLongLengthFormat

						$Bytes = $Reader.ReadBytes($LengthToReadNext)

						$Data = [System.BitConverter]::ToUInt64((Set-ByteArrayPadding -InputObject $Bytes -Length 8), 0)

						break
					}
					# Generalized String
					0x18 {
						$LengthToReadNext = Get-ASN1ValueLength -Reader $Reader -UseLongLengthFormat

						$Bytes = $Reader.ReadBytes($LengthToReadNext)

						$Data =  [System.Text.Encoding]::ASCII.GetString($Bytes)

						break
					}
					# BMPString / UNICODE_STRING
					0x1E {
						$LengthToReadNext = Get-ASN1ValueLength -Reader $Reader -UseLongLengthFormat

						$Bytes = $Reader.ReadBytes($LengthToReadNext)

						$Data = [System.Text.Encoding]::Unicode.GetString($Bytes)

						break
					}
					# SEQUENCE Type
					0x30 {
						$LengthToReadNext = Get-ASN1ValueLength -Reader $Reader -UseLongLengthFormat

						$Bytes = $Reader.ReadBytes($LengthToReadNext)

						[System.Collections.Hashtable]$Data = @{}

						break   
					}
					# Set
					0x31 {
						$LengthToReadNext = Get-ASN1ValueLength -Reader $Reader -UseLongLengthFormat

						$Bytes = $Reader.ReadBytes($LengthToReadNext)

						[System.Collections.Hashtable]$Data = @{}

						break
					}
					default {
						throw New-Object -TypeName System.ArgumentOutOfRangeException("The current position in the stream does not identify an known ASN.1 item, received: 0x$($Tag.ToString("X2"))")
					}
				}

				$Temp = @{"Tag" = $Tag; "Data" = $Data; "Length" = $LengthToReadNext }

				if ($Tag -in @(0x30, 0x31))
				{               
					# The data property is an empty hashtable, set it to the the items of the sequence 
					$Temp["Data"] = Read-ASN1Content -Content $Bytes
                    
					$Result.Add(($Counter++).ToString(), $Temp)
				}
				# Bit String or Octet Stream
				elseif ($Tag -in @(0x03, 0x04))
				{
					try 
					{
						$Temp["Data"] = Read-ASN1Content -Content $Bytes

						$Result.Add(($Counter++).ToString(), $Temp)
					}
					catch [System.ArgumentOutOfRangeException] {
						$Result.Add(($Counter++).ToString(), $Temp)
					}
				}
				# Otherwise this is a standard primitive like string, int, bool, OID, etc
				else
				{
					$Result.Add(($Counter++).ToString(), $Temp)
				}
			}

			Write-Output -InputObject $Result
		}
		finally
		{
			$Reader.Dispose()

			if ($MS -ne $null)
			{
				$MS.Dispose()
			}
		}
    }

    End {
    }
}