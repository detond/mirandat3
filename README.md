# mirandat3

The project has been forked from https://github.com/krig/mirandat.py

The original project is able to export history from Miranda IM dat-files.

My goal is to make the following changes to the project:
* port it to Python3 :heavy_check_mark:
* make sure it works with national encodings :heavy_check_mark:
* make the output slightly more readable :heavy_check_mark:
* add HTML export.

## Usage examples

Dump all chat logs from `miranda.dat` to stdout, set `Dan` as sender name for all outgoing messages:
```
./mirandat3.py miranda.dat ls --my-name Dan
```

List all contacts stored in `miranda.dat`, assume the encoding is Windows 1251 (Russian):
```
./mirandat3.py miranda.dat --encoding cp1251 cn
```

Save all chat logs from `miranda.dat` into `export` folder as separate files for each contact. Set `Vlad` as sender name for all outgoing messages, assume the encoding is Windows 1251 (Russian):
```
./mirandat3.py miranda.dat --encoding cp1251 ls --my-name Vlad --split export
```

Find a contact by ICQ UIN and type its full details to stdout:
```
./mirandat3.py miranda.dat fc UIN 12345678
```

For full usage options call `./mirandat3.py -h`