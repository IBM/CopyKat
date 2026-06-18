#!/bin/bash

ls ../repro-* | xargs -I {} sh -c 'echo {} && gdb -batch -ex "disassemble/r main" -ex "disassemble/r loop" -ex "disassemble/r execute_one" {} 2>/dev/null | grep "fopen64"' > fopen.locations
ls ../repro-* | xargs -I {} sh -c 'echo {} && gdb -batch -ex "disassemble/r main" -ex "disassemble/r loop" -ex "disassemble/r execute_one" {} 2>/dev/null | grep "fprintf"' > fprintf.locations
ls ../repro-* | xargs -I {} sh -c 'echo {} && gdb -batch -ex "disassemble/r main" -ex "disassemble/r loop" -ex "disassemble/r execute_one" {} 2>/dev/null | grep "fclose"' > fclose.locations

