
# PE-STAMAL

**Static Analysis** can be done by checking physical states of file. In our case , we used executable file as static samples and to check the physical states of windows executable file Windows provide Portable Executable Format (PE Format) which describes the structure of executable (image) files and object files under the Windows family of operating systems. These files are referred to as Portable Executable (PE) files.


## Description

Stand-alone Python script for analyze PE file header and sections (number of sections, entropy of sections, suspicious section names, suspicious flags in characteristics of PE file etc ...) .

I personally use this script almost daily during personal and professional research to quickly extract important information to determine if further analysis is needed .  

## Features

- File name
- File size
- File hashes (MD5, SHA1, SHA256, SSDeep, peHash, imphash)
- Compilation Time ( Is this time in the distant past or a future data ) 
- Entry Point
- Start Address
- PE Sections( Name, Size ,  Address , Entropy ) 
- Security Features (SEH , ASLR ,DEP)
- Check if PE is likely packed


 ## Example usage

```python
from pe_statmal import PEstatmal

s = PEstatmal("file.exe") #:Add filename

s.PE_imphash() #:Return ImportHash   
s.PE_type() #:Return Type File ("DLL", "DRIVER", "EXE") 
s.PE_arch() #:Return return architecteur (x86 , x64 , Itanium)
s.PE_hash()#:Return hash(MD5,SHA512, SHA256)
s.PE_check_antiVM()#:return Check if there an Anti Vmware Machines
s.PE_sections()#:return Section (name, address, virtual_size , size , entropy)
s.PE_entrypoint()#:return AddressOfEntryPoint
s.PE_imagebase()#:return IMageBase
s.PE_enty_import()#:return  EntryImports (Entry_Name , Symbols)
s.PE_entry_export()#:return  EntryExports (Address , Name , Ordinal )
s.PE_os()#:return  Os Version 	
s.PE_security()#:return Security (ASLR ,DEP ,SEH, and More )
s.PE_time()#:return TimeData Compiled	
s.run() #Return all fonctions 
 
```

## Installation
1. git clone https://github.com/svdwi/pe-statmal
2. cd pe_stamal && pip install -r requirements.txt
