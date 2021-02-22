
# pe2json
Copyright 2019-2021 Philippe Paquet


## Description
pe2json is a Python based command line utility that reads Portable Executables (PE) files and output JSON.

JSON output include all the PE internal structures such as:
* IMAGE_BASE_RELOCATION
* IMAGE_DEBUG_DIRECTORY
* IMAGE_DOS_HEADER
* IMAGE_EXPORT_DIRECTORY
* IMAGE_FILE_HEADER
* IMAGE_IMPORT_DESCRIPTOR
* IMAGE_LOAD_CONFIG_DIRECTORY
* IMAGE_NT_HEADERS
* IMAGE_OPTIONAL_HEADER
* IMAGE_RESOURCE_DATA_ENTRY
* IMAGE_RESOURCE_DIRECTORY
* IMAGE_RESOURCE_DIRECTORY_ENTRY
* IMAGE_SECTION_HEADER
* etc...
 
JSON output also include additional information such as:
* File Name
* File Size
* Imphash
* MD5
* SHA-1
* SHA-256
* SHA-512

For the specifications of the PE format, check Microsoft [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) documentation.

## Dependencies

pe2json requires the pefile python package created by [Ero Carrera](https://github.com/erocarrera). You can find pefile on [github](https://github.com/erocarrera/pefile) or [pypi](https://pypi.org/project/pefile/).

You can use the following command line to install pefile using pip.
```bash
pip install pefile
```
```bash
python3 -m pip install pefile
```

If you want to keep everything within one directory, you install pefile in a `packages` subdirectory.
```bash
pip install --target=packages pefile
```
```bash
python3 -m pip install --target=packages pefile
```

pe2json will recognize the `packages` subdirectory and will automatically import packages from that location first.

## Usage

Using pe2json is extremely simple.

```bash
python3 pe2json.py <input>
```

`input` can be either a file name or a directory name.

If `input` is a file name, the JSON output will be optimized for readability.

If `input` is a directory name, the JSON output will be one line per file (LDJSON or line delimited JSON).

Only files with the following extensions will be considered for analysis for directories:
* dll
* drv
* exe
* sys

## Example

In the example directory, you will find an example JSON output from analyzing `kernel32.dll` named `kernel32.dll.json`.

## Contributing

Bug reports and suggestions for improvements are most welcome.

## Contact

If you have any questions, comments or suggestions, do not hesitate to contact me at philippe@paquet.email
