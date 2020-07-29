#include <iostream>
#include <fstream>
#include <windows.h>
#include <vector>

DWORD readDword(std::vector<uint8_t> v, DWORD offset) {
    DWORD res = DWORD(0);
    uint8_t byte0 = *(v.begin() + offset);
    uint8_t byte1 = *(v.begin() + offset + 1);
    uint8_t byte2 = *(v.begin() + offset + 2);
    uint8_t byte3 = *(v.begin() + offset + 3);
    res = byte3 * 0x1000000 + byte2 * 0x10000 + byte1 * 0x100 + byte0;
    return res;
}

DWORD getElfanew(std::vector<std::uint8_t> v) {
    return (DWORD) *(v.begin() + 0x3c);
}

DWORD alignUp(DWORD sectionSize, DWORD sectionAlignment) {
    return (DWORD)sectionAlignment * (sectionSize / sectionAlignment) + sectionAlignment;
}

DWORD getSectionsRaw(std::vector<uint8_t> pe) {
    DWORD e_lfanew = getElfanew(pe);
    DWORD numOfDataDirsOffset = e_lfanew + 4 /*size of signature*/ + 0x14 /*size of image file header*/ + 0x5c /*NumberOfRvaAndSizes*/;
    DWORD numOfDataDirs = readDword(pe, numOfDataDirsOffset);
    DWORD sectionsBeginning = numOfDataDirsOffset + 4 /*size of DataDirsOffset*/ + numOfDataDirs * 8 /*size of data dir*/;
    return sectionsBeginning;
}

DWORD rva2raw(std::vector<uint8_t> pe, DWORD rva) {
    DWORD raw = NULL;
    DWORD sectionsBeginning = getSectionsRaw(pe);
    WORD numberOfSections = *(pe.begin() + getElfanew(pe) + 4 + 2); // bug. dosn't work if both bytes of NumbereOfSections are siginificant
    for (int i = 0; i < numberOfSections; i++) {
        DWORD sectionOffset = sectionsBeginning + i * 0x28 /*size of section*/;
        DWORD sectionRva = readDword(pe, DWORD(sectionOffset + 0xC /*rva*/));
        DWORD sectionVirtSize = readDword(pe, DWORD(sectionOffset + 0x8 /*size*/));
        DWORD sectionAlignment = 0x1000;
        if (rva >= sectionRva && rva < sectionRva + alignUp(sectionVirtSize, sectionAlignment)) {
            DWORD offset = rva - sectionRva;
            DWORD rawSection = readDword(pe, sectionOffset + 0x14 /*raw offset*/);
            raw = rawSection + offset;
            break;
        }

    }
    if (raw == NULL) {
        printf("raw not found");
        exit(2);
    }
    return raw;
}

DWORD rva2va(DWORD rva, LPVOID imageBase) {
    return (DWORD) ((uint8_t*)imageBase + rva);
}

DWORD getSizeOfHeaders(std::vector<uint8_t> pe) {
    DWORD offset = getElfanew(pe) + 4 /*size of signature*/ + 0x14 /*size of file header*/ + 0x3c /*size of headres offset*/;
    return readDword(pe, offset);
}

DWORD getSizeOfImage(std::vector<uint8_t> pe) {
    DWORD e_lfanew = getElfanew(pe);
    DWORD sizeOfImageOffset = e_lfanew + 4 /*size of signature*/ + 0x14 /*size of fileHeader*/ + 0x38;
    return readDword(pe, sizeOfImageOffset);
}

DWORD getImportTableRva(LPVOID pe) {
    DWORD e_lfanew = *((DWORD*)((uint8_t*)pe + 0x3c));
    DWORD importTableOffset = e_lfanew + 4 /*size of signature*/ + 0x14 /*size of fileHeader*/ + 0x60 /*dataDirs offset*/ + 1 * 8;
    LPVOID importTablePtr = (uint8_t*)pe + importTableOffset;
    DWORD importTableRva = *(DWORD*) importTablePtr;
    return importTableRva;
}

DWORD getRellocTableRva(LPVOID pe) {
    DWORD e_lfanew = *((DWORD*)((uint8_t*)pe + 0x3c));
    DWORD rellocTableOffset = e_lfanew + 4 /*size of signature*/ + 0x14 /*size of fileHeader*/ + 0x60 /*dataDirs offset*/ + 5 * 8;
    LPVOID rellocTablePtr= (uint8_t*)pe + rellocTableOffset;
    return *(DWORD*)rellocTablePtr;
}

DWORD getEntryPoint(LPVOID pe) {
    DWORD e_lfanew = *((DWORD*)((uint8_t*)pe + 0x3c));
    DWORD entryPointOffset = e_lfanew + 4 /*size of signature*/ + 0x14  /*size of fileHeader*/ + 0x10;
    return *(DWORD*)((uint8_t*)pe + entryPointOffset);
}

DWORD getOrigImageBase(LPVOID pe) {
    DWORD e_lfanew = *((DWORD*)((uint8_t*)pe + 0x3c));
    DWORD imageBaseOffset = e_lfanew + 4 + 0x14 + 0x1c;
    return *(DWORD*)((uint8_t*)pe + imageBaseOffset);
}


std::vector<std::uint8_t> file2vec(LPCSTR filePath) {
    std::ifstream fileStream(filePath, std::ios_base::in | std::ios_base::binary);
    if (!fileStream.is_open()) {
        printf("error");
        exit(2);
    }
    fileStream.seekg(0, std::ios_base::end);
    std::streampos fileSize = fileStream.tellg();
    std::vector<std::uint8_t> peVector(fileSize);
    fileStream.seekg(0, std::ios_base::beg);
    fileStream.read((char*)peVector.data(), fileSize);
    return peVector;
}

int main() {
    std::vector<std::uint8_t> simplePE = file2vec("./SIMPLE_PE.exe");
    DWORD sizeOfHeaders = getSizeOfHeaders(simplePE);
    DWORD sizeOfImage = getSizeOfImage(simplePE);

    LPVOID peImageBase = VirtualAlloc(NULL, (SIZE_T) sizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("SIMPLE_PE.EXE new image Base: 0x%x\n", (DWORD)peImageBase);

    printf("Load dos header\n");
    MoveMemory(peImageBase, simplePE.data(), sizeOfHeaders);
    

    printf("Load sections\n");
    DWORD sections = getSectionsRaw(simplePE);
    for (int i = 0; i < 3; i++) {
        DWORD sectionOffset = sections + i * 0x28 /*size of section*/;
        DWORD sectionRva = readDword(simplePE, DWORD(sectionOffset + 0xC /*rva*/));
        DWORD rawSize = readDword(simplePE, DWORD(sectionOffset + 0x8));
        DWORD sectionRaw = rva2raw(simplePE, sectionRva);
        MoveMemory((uint8_t*) peImageBase + sectionRva, simplePE.data() + sectionRaw, rawSize);
    }

    printf("Edit import table\n");
    DWORD importTableRva = getImportTableRva(peImageBase);
    LPVOID curImportTableEntryOffset = (uint8_t*)peImageBase + importTableRva;
    do {
        DWORD moduleNameRva = *((DWORD*)((uint8_t*)curImportTableEntryOffset + 0xC));
        LPCSTR moduleNamePtr = (LPCSTR)(moduleNameRva + (uint8_t*)peImageBase);
        HMODULE hMod = LoadLibraryA(moduleNamePtr);

        DWORD imageThunkDataRva = *((DWORD*)((uint8_t*)curImportTableEntryOffset + 0x10));
        DWORD imageThunkDataEntry = rva2va(imageThunkDataRva, peImageBase);
        while (*(DWORD*)imageThunkDataEntry != 0){
            DWORD imageImportByName = rva2va(*(DWORD*)imageThunkDataEntry, peImageBase);
            LPCSTR funcName = (LPCSTR)((uint8_t*)imageImportByName + 2);
            LPVOID funcAddr = GetProcAddress(hMod, funcName);
            *(DWORD*)imageThunkDataEntry = (DWORD)funcAddr;
            imageThunkDataEntry = imageThunkDataEntry + 4;
        }
        curImportTableEntryOffset = (uint8_t*)curImportTableEntryOffset + 0x14 /*size of Import Table Descriptor*/;
    } while (*((DWORD*) curImportTableEntryOffset) != NULL);

    printf("Edit relloc table\n");
    DWORD rellocTableRva = getRellocTableRva(peImageBase);
    DWORD rellocTable = rva2va(rellocTableRva, peImageBase);
    DWORD sectionRva = *(DWORD*)rellocTable;
    DWORD sizeOfBlock = *(DWORD*)(rellocTable + 4);
    DWORD origImageBase = getOrigImageBase(peImageBase);
    for (int i = 0; i < (sizeOfBlock - 8)/2; i++) {
        DWORD sectionOffset = *((uint8_t*)(rellocTable + 2 * 4 + 2 * i));
        DWORD funcAddrPtr = rva2va(sectionRva, peImageBase) + sectionOffset;
        DWORD funcAddr = *(DWORD*)funcAddrPtr;
        DWORD newFuncAddr = funcAddr - origImageBase + (DWORD)peImageBase;
        *(DWORD*) funcAddrPtr = newFuncAddr;
    }

    printf("Give exec control to the entry point\n");
    DWORD entryPointRva = getEntryPoint(peImageBase);
    DWORD entryPoint = rva2va(entryPointRva, peImageBase);
    typedef void (*fn)();
    fn simplePeMain = (fn)entryPoint;
    simplePeMain();
    return 0;
}




