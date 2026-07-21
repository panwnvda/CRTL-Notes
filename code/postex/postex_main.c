/*
 * Postex Kit — PostexMain Examples
 *
 * The postex-kit is a Visual Studio solution for authoring custom
 * post-exploitation DLLs. The full C runtime is available within
 * PostexMain. Supports both simple (execute-dll) and multi-arg
 * (beacon_execute_postex_job) execution paths.
 *
 * Bidirectional communication is supported via BeaconInputAvailable
 * and BeaconInputRead on the named pipe.
 */

#include <windows.h>
#include "beacon.h"

/* ---- Simple single-arg example ---- */

void PostexMain_Simple(PPOSTEX_DATA postexData) {
    RETURN_ON_NULL(postexData);
    BeaconPrintf(CALLBACK_OUTPUT, "You said: %s", postexData->UserArgumentInfo.Buffer);
}

/* ---- Multi-arg via bof_pack ---- */

void PostexMain(PPOSTEX_DATA postexData) {
    RETURN_ON_NULL(postexData);
    datap parser;
    char *name;
    int   age;

    BeaconDataParse(&parser, postexData->UserArgumentInfo.Buffer,
                              postexData->UserArgumentInfo.Size);
    name = BeaconDataExtract(&parser, NULL);
    age  = BeaconDataInt(&parser);

    BeaconPrintf(CALLBACK_OUTPUT, "Your name is %s and you are %d years old", name, age);
}

/* ---- Bidirectional communication loop ---- */

BOOL ClientConnected() {
    if (!PeekNamedPipe(gPipeHandle, NULL, 0, NULL, NULL, 0)) {
        if (GetLastError() == ERROR_BROKEN_PIPE) return FALSE;
    }
    return TRUE;
}

void PostexMain_LongRunning(PPOSTEX_DATA postexData) {
    RETURN_ON_NULL(postexData);

    while (TRUE) {
        DWORD bytesAvailable = BeaconInputAvailable();
        if (bytesAvailable > 0) {
            char *pipeData = new char[bytesAvailable]();
            BeaconInputRead(pipeData, bytesAvailable);
            /* handle inbound data */
            delete[] pipeData;
        }

        Sleep(60 * 1000);
        if (!ClientConnected()) break;   /* Beacon jobkill closes pipe */
    }
}
