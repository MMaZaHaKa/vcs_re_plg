#include "Windows.h"
#include "assert.h"
#include <iostream>
#include <stdio.h>
#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <algorithm>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <iomanip>


#define null NULL
#define nil NULL

void SetColor(WORD wAttributes)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, wAttributes);
}
void copyToClipboard(const char* text)
{
	if (OpenClipboard(NULL))
	{
		EmptyClipboard();
		size_t len = strlen(text) + 1;
		HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
		if (hMem) { memcpy(GlobalLock(hMem), text, len); GlobalUnlock(hMem); SetClipboardData(CF_TEXT, hMem); }
		CloseClipboard();
	}
}
void MboxSTD(std::string msg, std::string title = "") { MessageBoxA(HWND_DESKTOP, msg.c_str(), title.c_str(), MB_SYSTEMMODAL | MB_ICONWARNING); }

#include <signal.h>
const int re3_buffsize = 1024;
static char re3_buff[re3_buffsize];
void re3_assert(const char* expr, const char* filename, unsigned int lineno, const char* func)
{
	int nCode;

	strcpy_s(re3_buff, re3_buffsize, "Assertion failed!");
	strcat_s(re3_buff, re3_buffsize, "\n");

	strcat_s(re3_buff, re3_buffsize, "File: ");
	strcat_s(re3_buff, re3_buffsize, filename);
	strcat_s(re3_buff, re3_buffsize, "\n");

	strcat_s(re3_buff, re3_buffsize, "Line: ");
	_itoa_s(lineno, re3_buff + strlen(re3_buff), re3_buffsize - strlen(re3_buff), 10);
	strcat_s(re3_buff, re3_buffsize, "\n");

	strcat_s(re3_buff, re3_buffsize, "Function: ");
	strcat_s(re3_buff, re3_buffsize, func);
	strcat_s(re3_buff, re3_buffsize, "\n");

	strcat_s(re3_buff, re3_buffsize, "Expression: ");
	strcat_s(re3_buff, re3_buffsize, expr);
	strcat_s(re3_buff, re3_buffsize, "\n");

	strcat_s(re3_buff, re3_buffsize, "\n");
	strcat_s(re3_buff, re3_buffsize, "(Press Retry to debug the application)");


	nCode = ::MessageBoxA(nil, re3_buff, "REVCS Assertion Failed!",
		MB_ABORTRETRYIGNORE | MB_ICONHAND | MB_SETFOREGROUND | MB_TASKMODAL);

	if (nCode == IDABORT)
	{
		raise(22/*SIGABRT*/);
		_exit(3);
	}

	if (nCode == IDRETRY)
	{
		__debugbreak();
		return;
	}

	if (nCode == IDIGNORE)
		return;

	abort();
}
#define myassert(_Expression) (void)((!!(_Expression)) || (re3_assert(#_Expression, __FILE__, __LINE__, __FUNCTION__), 0))


#define CW_R() SetColor(FOREGROUND_RED)                               // Красный
#define CW_G() SetColor(FOREGROUND_GREEN)                             // Зеленый
#define CW_B() SetColor(FOREGROUND_BLUE)                              // Синий
#define CW_Y() SetColor(FOREGROUND_RED | FOREGROUND_GREEN)            // Желтый
#define CW_C() SetColor(FOREGROUND_GREEN | FOREGROUND_BLUE)           // Голубой (Cyan)
#define CW_M() SetColor(FOREGROUND_RED | FOREGROUND_BLUE)             // Магента (Magenta)
#define CW_W() SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE) // Белый
#define CW_K() SetColor(0)                                            // Черный (выключить все цвета)

//static inline uintptr_t EEMainMemoryStart = 0/*0x20000000*/;
//static inline uintptr_t EEMainMemoryEnd = 0/*0x21ffffff*/;

struct MemoryRegion { void* baseAddress; SIZE_T size; };
std::vector<MemoryRegion> inline FindRegions(SIZE_T targetSize = 0, DWORD targetType = 0, DWORD targetProtect = 0, DWORD targetState = MEM_COMMIT) {
	std::vector<MemoryRegion> regions;
	MEMORY_BASIC_INFORMATION mbi;
	uintptr_t address = 0;
	while (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi)) != 0) {
		if (targetSize != 0 && mbi.RegionSize != targetSize) { address += mbi.RegionSize; continue; }
		if (targetType != 0 && mbi.Type != targetType) { address += mbi.RegionSize; continue; }
		if (targetProtect != 0 && mbi.Protect != targetProtect) { address += mbi.RegionSize; continue; }
		if (targetState != 0 && mbi.State != targetState) { address += mbi.RegionSize; continue; }
		regions.push_back({ mbi.BaseAddress, mbi.RegionSize });
		address += mbi.RegionSize;
	}
	return regions;
}

void* SearchPointerByPattern(void* ptrStart, int block_size, std::string pattern)
{
#define INRANGE(x, a, b) (x >= a && x <= b)
#define getBits(x) (INRANGE((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xa) : (INRANGE(x, '0', '9') ? x - '0' : 0))
#define getByte(x) (getBits(x[0]) << 4 | getBits(x[1]))
	const char* buffptr_pattern = pattern.c_str();
	uintptr_t pMatch = 0;
	for (uintptr_t MemPtr = (uintptr_t)ptrStart; MemPtr < ((uintptr_t)ptrStart + block_size); MemPtr++)
	{
		if (!*buffptr_pattern) { break; }
		if (*(PBYTE)buffptr_pattern == '\?' || *(BYTE*)MemPtr == getByte(buffptr_pattern))
		{
			if (!pMatch) { pMatch = MemPtr; }
			if (!buffptr_pattern[2]) { break; } // паттерн закончился
			//PWORD первых 2 символа из паттерна, PBYTE первый символ
			if (*(PWORD)buffptr_pattern == '\?\?' || *(PBYTE)buffptr_pattern != '\?') { buffptr_pattern += 3; }
			else { buffptr_pattern += 2; } //one ?
		}
		else
		{ // срыв совпадения
			buffptr_pattern = pattern.c_str();
			if (pMatch) { MemPtr = pMatch; }
			pMatch = 0;
		}
	}
	//free((void*)buffptr_pattern); // GetProcAddressNoExternCExport
	if (!pMatch) { return NULL; }
	//printf("found str: 0x%p\n", (char*)pMatch);
	return (void*)pMatch;
#undef getByte;
#undef getByte;
#undef INRANGE;
}

inline static uintptr_t CalcPointerFromOffset(uintptr_t op_addr, uintptr_t offset) // call offset => pointer func (restore)
{
	return (op_addr + 1 + sizeof(uintptr_t) + offset);
}
// op_addr , dest pointer, Relative
inline static uintptr_t CalcOffset(uintptr_t op_addr, void* dest_ptr) { return ((uintptr_t)dest_ptr - (op_addr + 1 + sizeof(uintptr_t))); }
inline static void* Relative(void* to, void* address) { return (void*)((int)to - (unsigned int)address - sizeof address); } // same

// same
inline static uintptr_t CalcOffset(uintptr_t op_addr, uintptr_t dst) { return (dst - (op_addr + 1 + sizeof(uintptr_t))); } // W
//inline static uintptr_t CalcPointerFromOffset(uintptr_t op_addr, uintptr_t offset) { return (op_addr + 1 + sizeof(uintptr_t) + offset); } // R


// GET_REG(eax, _eax); printf("eax: 0x%p\n", _eax);
#define GET_REG(reg, varname) \
    uint32_t varname; \
    __asm { mov varname, reg }
// SET_REG(ecx, 0xFF)
#define SET_REG(reg, value) \
    __asm { mov reg, value }
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#define ALIGN4BYTES(s) ((((uint32_t)s) + 3) & 0xFFFFFFFC) // re3 pcsave
template <typename T, typename R = uint32_t> R inline _stackcast(T v) { return *((R*)&v); } // const reinterpret_cast (stack)
#define BYTESF2U32(f) _stackcast<float, uint32_t>(f)
#define BIT(num) (1<<(num)) // mask BIT[31...0] (x86 Little Endian)
#define GET_BITS(value, mask, shift) (((value) & (mask)) >> (shift))
#define GET_BIT(num, n) (((num) >> (n)) & 1) // 11111111(3) 11111111(2) 11111101(1) 11111111(0) mem(FF FD FF FF), 32t_byte1, bit[76543210] <- 1<<(N1)
#define SET_BIT(num, n, val) ((num) = ((num) & ~BIT(n)) | ((val) << (n)))
#define GET_BYTE(num, n) ((num >> (8 * n)) & 0xFF) // 0-lob, 1-midlob, 2-midhib, 3-hib BYTE[0123] (x86 Little Endian)
#define SET_BYTE(num, n, val) ((num) = ((num) & ~(0xFF << (8 * (n)))) | ((val) << (8 * (n))))
#define SWAP_BIT(num, n) SET_BIT(num, n, !GET_BIT(num, n))
#define DUMP_BITS(num) (printf("%d%d%d%d%d%d%d%d\n", GET_BIT(num, 7), GET_BIT(num, 6), \
	GET_BIT(num, 5), GET_BIT(num, 4), GET_BIT(num, 3), GET_BIT(num, 2), GET_BIT(num, 1), GET_BIT(num, 0)))
#define DUMP_BITS2(num) (printf("0_[%d], 1_[%d], 2_[%d], 3_[%d], 4_[%d], 5_[%d], 6_[%d], 7_[%d]\n", GET_BIT(num, 7), GET_BIT(num, 6), \
	GET_BIT(num, 5), GET_BIT(num, 4), GET_BIT(num, 3), GET_BIT(num, 2), GET_BIT(num, 1), GET_BIT(num, 0)))
#define SWAP_ENDIAN(x) ( \
    (((uint32_t) (x) & 0x000000ff) << 24) | \
    (((uint32_t) (x) & 0x0000ff00) <<  8) | \
    (((uint32_t) (x) & 0x00ff0000) >>  8) | \
    (((uint32_t) (x) & 0xff000000) >> 24) \
) // PS2 SDK
#define OFFSET(base, off, type) ((type)&(((uint8_t*)base)[off]) )
#define TEST_OFFSET(obj, field, offset) assert(((uint8_t*)&obj) == (((uint8_t*)&field) - offset))
#define TEST_POFFSET(pobj, pfield, offset) assert(((uint8_t*)pobj) == (((uint8_t*)pfield) - offset))
// PDP-10 like byte functions
#define MASK(p, s) (((1 << (s)) - 1) << (p))
inline uint32_t dpb(uint32_t b, uint32_t p, uint32_t s, uint32_t w) { uint32_t m = MASK(p, s); return (w & ~m) | ((b << p) & m); } // Deposit Bit Field
inline uint32_t ldb(uint32_t p, uint32_t s, uint32_t w) { return w >> p & (1 << s) - 1; } // Load Bit Field
#define INRANGE(x,a,b) (x >= a && x <= b) // xarex1337
#define getBits( x ) (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x ) (getBits(x[0]) << 4 | getBits(x[1]))
//template<typename T> T inline EMUPOINTER(void* p) { return (T)(p ? PCSX2POINTER(p) : null); } // need?
#define VU2V(v) (*(CVector*)(&v))
#define V2VU(v) (*(CVuVector*)(&v))
#define debug(f, ...) printf(f, ##__VA_ARGS__)
uint32_t align(uint32_t o, uint32_t n) { return o+n-1 & ~(n-1); }


#define RWRGBAINT(r, g, b, a) ((uint32)((((a)&0xff)<<24)|(((b)&0xff)<<16)|(((g)&0xff)<<8)|((r)&0xff)))
#define PI (3.1415f)
#define TWOPI (PI * 2)
#define HALFPI (PI / 2)
#define DEGTORAD(x) ((x) * PI / 180.0f)
#define RADTODEG(x) ((x) * 180.0f / PI)

#define MYDLL_EXPORTS
#define MAZAHAKA // PCSX2 ver 1.6.0 x86  SLUS-215.90
#ifdef MYDLL_EXPORTS
#define MYDLL_API __declspec(dllexport)
#else
#define MYDLL_API __declspec(dllimport)
#endif

extern "C" void MYDLL_API Loader_Dummy() {} // creating export table. cff explorer-> import adder


template<typename T>
void inline patch(uintptr_t address, T value/*, bool idaptr = false*/)
{
	DWORD vp[2];
	//if (idaptr) { address = IDATRANSLATE(address); }
	T* ptr = reinterpret_cast<T*>(address);
	VirtualProtect(ptr, sizeof(T), PAGE_EXECUTE_READWRITE, &vp[0]);
	*ptr = value;
	VirtualProtect(ptr, sizeof(T), vp[0], &vp[1]);
}
template<typename T>
void inline patch(void* address, T value/*, bool idaptr = false*/) { patch<T>((uintptr_t)address, value/*, idaptr*/); }
//#define IDApatch(p, t, v) patch<t>(IDATRANSLATE(p), v); // 	IDApatch(0x123, char, 77);
#define SET_VAL_NOVP patch
void inline patchblock(uintptr_t pto, uintptr_t pfrom, uint32_t size/*, bool idaptr = false*/)
{
	DWORD vp[2];
	if (!pto || !pfrom || !size) { printf("err patch\n"); return; }
	//if (idaptr) { pfrom = IDATRANSLATE(address); }
	VirtualProtect((void*)pto, size, PAGE_EXECUTE_READWRITE, &vp[0]);
	memcpy((void*)pto, (void*)pfrom, size);
	VirtualProtect((void*)pto, size, vp[0], &vp[1]);
}
void inline patchblock(uintptr_t pto, void* pfrom, uint32_t size/*, bool idaptr = false*/) { patchblock((uintptr_t)pto, (uintptr_t)pfrom, size); }
void inline patchblock(void* pto, uintptr_t pfrom, uint32_t size/*, bool idaptr = false*/) { patchblock((uintptr_t)pto, (uintptr_t)pfrom, size); }
void inline patchblock(void* pto, void* pfrom, uint32_t size/*, bool idaptr = false*/) { patchblock((uintptr_t)pto, (uintptr_t)pfrom, size); }
void inline patchstring(uintptr_t pto, char* str) { if (str) { patchblock(pto, str, strlen(str) + 1); } }
void inline patchstring(void* pto, char* str) { patchstring((uintptr_t)pto, str); }


#define is_valid_pointer(a) 1
class MemoryPatcher
{
public:
	uintptr_t address;
	std::vector<uint8_t> originalBytes;
	std::vector<uint8_t> patchBytes;
	int size;
	bool isPatched;
	MemoryPatcher() {}
	MemoryPatcher(uintptr_t addr, uint8_t val, uint32_t cnt) : isPatched(false)//, address(addr), size(cnt)
	{
		if (!addr || !cnt || !is_valid_pointer((void*)addr)) { return; }
		address = addr; // 0 if !valid
		size = cnt;
		for (size_t i = 0; i < size; i++) { patchBytes.push_back(val); }
	}
	MemoryPatcher(uintptr_t addr, std::vector<uint8_t> patchData) : isPatched(false)//, address(addr)
	{
		if (!addr || !patchData.size() || !is_valid_pointer((void*)addr)) { return; }
		address = addr; // 0 if !valid
		patchBytes = patchData;
		size = patchBytes.size();
	}
	void inline ApplyPatch()
	{
		if (!originalBytes.size()) { for (int i = 0; i < size; i++) { originalBytes.push_back(((uint8_t*)address)[i]); } }
		if (size && !isPatched) { patchblock(address, patchBytes.data(), patchBytes.size()); isPatched = true; printf("[0x%p/%d]: Ena\n", address, size); }
	}
	void inline RemovePatch() { if (size && isPatched) { patchblock(address, originalBytes.data(), originalBytes.size()); isPatched = false; printf("[0x%p/%d]: Disa\n", address, size); } }
};



HANDLE InitConsole() // with proto
{
	AllocConsole();

	//SetConsoleOutputCP(866);
	setlocale(LC_ALL, "Russian");
	SetConsoleOutputCP(1251);
	SetConsoleCP(1251);


	freopen("CONIN$", "r", stdin);
	freopen("CONOUT$", "w", stdout);

	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);

	return hConsole;
}

void SetConsoleColor(int32_t mode)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (mode == 0)
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
	else if (mode == 1)
		SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
	else if (mode == 2)
		SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE);
	else if (mode == 3)
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN);
	else if (mode == 4)
		SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_BLUE);
	else if (mode == 5)
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_BLUE);
	else if (mode == 6)
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	else if (mode == 7)
		SetConsoleTextAttribute(hConsole, 0);
}

std::vector<std::string> FileReadAllLines(std::string filePath)
{

	std::vector<std::string> lines;
	std::ifstream file(filePath);

	if (!file.is_open()) { return lines; }

	std::string line;
	while (std::getline(file, line)) {
		lines.push_back(line);
	}

	file.close();
	return lines;
}

std::vector<uint8_t> FileReadAllBytes(std::string filePath)
{
	std::vector<uint8_t> buffer;
	std::ifstream file(filePath, std::ios::binary | std::ios::ate);
	if (!file.is_open()) { return buffer; }
	std::streamsize size = file.tellg();
	buffer.resize(size);
	file.seekg(0, std::ios::beg);
	if (!file.read((char*)(buffer.data()), size)) { return buffer; }
	return buffer;
}

bool FileWriteAllBytes(std::string filePath, std::vector<uint8_t>& buffer)
{
	std::ofstream file(filePath, std::ios::binary);
	if (!file.is_open()) { return false; }
	file.write((char*)(buffer.data()), buffer.size());
	return file.good();
}

bool FileWriteAllBytes(std::string filePath, const uint8_t* buffer, uint32_t size)
{
	std::ofstream file(filePath, std::ios::binary);
	if (!file.is_open()) { return false; }
	file.write((char*)(buffer), size);
	return file.good();
}

void U_SetCurrentDirectory()
{
	char currentDir[MAX_PATH]; // dynamic set curr dir to exe
	GetModuleFileNameA(NULL, currentDir, MAX_PATH);
	std::string::size_type pos = std::string(currentDir).find_last_of("\\/");
	SetCurrentDirectoryA(std::string(currentDir).substr(0, pos).c_str());
}

void PrintCurrDir()
{
	char buffer[MAX_PATH];  // MAX_PATH is typically 260
	DWORD length = GetCurrentDirectoryA(MAX_PATH, buffer);
	if (!length || length > MAX_PATH) { return; }
	printf("Current directory: %s\n", buffer);
}

std::string ClearStr(std::string input, std::string charsToRemove) {
	std::string result = input;
	result.erase(std::remove_if(result.begin(), result.end(),
		[&charsToRemove](char c) { return charsToRemove.find(c) != std::string::npos; }),
		result.end());
	return result;
}

static inline bool is_printable_ascii(uint8_t c) {
	return c >= 0x20 && c <= 0x7e;
}

void DataToHexString(int indent, uintptr_t startAddr, const uint8_t* data, size_t size, std::string* output) {
	if (!output) return;
	output->clear();
	if (!data || size == 0) return;

	// reserve approximate size: address + 3 chars per byte + ascii columns and newlines
	//output->reserve((size / 16 + 1) * (indent + 10 + 16 * 3 + 1 + 16));

	int addr_width = static_cast<int>(sizeof(uintptr_t) * 2);
	output->reserve((size / 16 + 1) * (indent + addr_width + 2 + 16 * 3 + 1 + 16));

	char buf[64];

	for (size_t i = 0; i < size; ++i) {
		if (i && (i % 16 == 0)) {
			// print ASCII for previous 16 bytes
			output->push_back(' ');
			size_t start = i - 16;
			for (size_t j = start; j < i; ++j) {
				output->push_back(is_printable_ascii(data[j]) ? static_cast<char>(data[j]) : '.');
			}
			output->push_back('\n');
		}

		//if ((i % 16) == 0) {
		//	// indent spaces
		//	if (indent > 0) output->append(std::string(static_cast<size_t>(indent), ' '));
		//	// address: 8 hex digits and two spaces after
		//	// cast to unsigned for printf
		//	unsigned addr_val = static_cast<unsigned>(startAddr + static_cast<uint32_t>(i));
		//	int n = std::snprintf(buf, sizeof(buf), "%08x  ", addr_val);
		//	output->append(buf, static_cast<size_t>(n));
		//}

		if ((i % 16) == 0) {
			// indent spaces
			if (indent > 0) output->append(std::string(static_cast<size_t>(indent), ' '));

			uintptr_t addr = static_cast<uintptr_t>(startAddr) + static_cast<uintptr_t>(i);
			std::string addr_str;
			addr_str.resize(static_cast<size_t>(addr_width), '0');

			uintptr_t tmp = addr;
			for (int pos = addr_width - 1; pos >= 0; --pos) {
				uint8_t nibble = static_cast<uint8_t>(tmp & 0xF);
				const char* hex_digits = "0123456789ABCDEF";
				addr_str[static_cast<size_t>(pos)] = hex_digits[nibble];
				tmp >>= 4;
			}
			output->append(addr_str);
			output->append("  ");
		}

		int n = std::snprintf(buf, sizeof(buf), "%02x ", data[i]);
		output->append(buf, static_cast<size_t>(n));
	}

	// If last line wasn't complete, add padding for hex columns
	if (size & 15) {
		size_t padded_size = ((size - 1) | 15) + 1;
		for (size_t j = size; j < padded_size; ++j) {
			output->append("   "); // three chars for each missing byte ("xx ")
		}
	}

	// Print ASCII for the final line (if any bytes exist)
	if (size > 0) {
		output->push_back(' ');
		size_t base = (size - 1) & ~static_cast<size_t>(0xF); // start index of the last 16-block
		for (size_t j = base; j < size; ++j) {
			output->push_back(is_printable_ascii(data[j]) ? static_cast<char>(data[j]) : '.');
		}
	}
}

float GetRandomFloatInc(float low, float high) {
	if (low == high) return low;
	if (low > high) std::swap(low, high);
	float t = static_cast<float>(rand()) / static_cast<float>(RAND_MAX);
	return low + t * (high - low);
}

inline bool BTN(int c) { return (GetAsyncKeyState(c) & 0x8000); }

// MEM_MAPPED -> SPACE - > 1ST BIN BYTE
#define ELF_BASE_OFFSET (0x1C004000 - 0x1B800000) // 1st bytes bin in ida - MEM_MAPPED base = StartOffset
#define PSP_BASE 0x08804000 // starts from
uintptr_t PPSSPP_BASE = 0; // pointer to 1st byte elf
#define PSPPOINTER(p)  ( (p) ? ((((uintptr_t)p) - PSP_BASE) + PPSSPP_BASE) : null ) // pPSP(ida) -> pPSP(win) (null saving)
#define PSPTRANSLATE(p) ( (p) ? ((((uintptr_t)p) - PPSSPP_BASE) + PSP_BASE) : null ) // pPSP(win) -> pPSP(ida) (null saving)
#define IDATRANSLATE(p) ((((uintptr_t)p) - PSP_BASE) + PPSSPP_BASE) /*PSPPOINTER(p)*/ // null non save

//template<typename T> T inline EMUPOINTER(void* p) { return (T)(p ? PSPPOINTER(p) : null); } // need?
template<typename T> T inline EMUPOINTER(void* p) { return (T)(PSPPOINTER(p)); } // need? moved to define
template<typename T> T inline EMUPOINTER(uintptr_t p) { return EMUPOINTER<T>((void*)p); } // need?


#pragma pack(push, 1)
/* 507 */
struct CControllerState
{
	__int16 LeftStickX;
	__int16 LeftStickY;
	__int16 RightStickX;
	__int16 RightStickY;
	__int16 LeftShoulder1;
	__int16 LeftShoulder2;
	__int16 RightShoulder1;
	__int16 RightShoulder2;
	__int16 DPadUp;
	__int16 DPadDown;
	__int16 DPadLeft;
	__int16 DPadRight;
	__int16 unk_nipple_up_field_18;
	__int16 unk_nipple_down_field_1A;
	__int16 unk_nipple_left_field_1C;
	__int16 unk_nipple_right_field_1E;
	__int16 Start;
	__int16 Select;
	__int16 Square;
	__int16 Triangle;
	__int16 Cross;
	__int16 Circle;
	__int16 LeftShock;
	__int16 RightShock;
};
struct CPad
{
	__int16 field_0;
	CControllerState NewState;
	CControllerState OldState;
	char field_62[48];
	__int16 Mode;
	__int16 field_94;
	__int16 DisablePlayerControls;
	char field_98[13];
	char KeyBoardCheatString[12];
	char field_B1[31];
	float field_D0;
};
struct CVector2D
{
	float x;
	float y;
};
struct CVuVector
{
	float x;
	float y;
	float z;
	float w;
};
struct __declspec(align(4)) RwV3d
{
	float x;
	float y;
	float z;
};
struct RwMatrix
{
	RwV3d right;
	int field_C;
	RwV3d up;
	int field_1C;
	RwV3d forvard_at;
	int field_2C;
	RwV3d pos;
	int field_3C;
};
void inline SetCVector4VU(CVuVector* p1, CVuVector* p2) { if (p1 && p2) { memcpy(p1, p2, 3 * 4); } }
void inline SetRWV3D(RwV3d* p1, CVuVector* p2) { memcpy(p1, p2, 3 * 4); }
struct CMatrix
{
	CVuVector right;
	CVuVector at_forward;
	CVuVector up;
	CVuVector pos;
	RwMatrix* m_pRwMat;
};
/* 528 */
struct CMatrixAlign
{
	CMatrix matrix;
	int field_44;
	int m_nFlags;
	int field_4C;
};
static_assert(sizeof(CMatrixAlign) == 0x50, "(sizeof(CMatrixAlign)"); // from lcs log too
struct CPlaceable
{
	CMatrix m_pMat;
};
struct __declspec(align(4)) RwLLLink
{
	RwLLLink* next;
	RwLLLink* prev;
};
struct RwLinkList
{
	RwLLLink link;
};
struct RwObject
{
	char type;
	char subType;
	char flags;
	char privateFlags;
	RwObject* parent;
};
struct RwObjectHasFrame
{
	RwObject object;
	RwLLLink lFrame;
	int sync;
};
struct ClumpExt
{
	int visibilityCallBack;
	int alpha;
};
struct CRGBA
{
	unsigned __int8 red;
	unsigned __int8 green;
	unsigned __int8 blue;
	unsigned __int8 alpha;
};
struct cRGB
{
	char r;
	char g;
	char b;
};
struct RwTexDictionary
{
	RwObject object;
	RwLinkList textures__texturesInDict;
	RwLLLink lInInstance;
};
struct RwRaster
{
	int unk1;
	int unk2;
	char* data;
	int flags;
};
struct RwTexture
{
	RwRaster* raster;
	RwTexDictionary* dict;
	RwLLLink lInDictionary;
	char name[32];
	char mask[32];
	int refCount; // ?
	int field_54; // ?
};
struct RpMaterial
{
	RwTexture* texture;
	CRGBA color;
	__int16 refCount;
	__int16 pad;
	int unk2;
};
struct RpMaterialList
{
	RpMaterial** materials;
	int numMaterials;
	int space;
};
struct sPspGeometry
{
	int size;
	int flags;
	int numStrips;
	int unk1;
	float bound[4];
	float scale[3];
	int numVerts;
	float pos[3];
	int unk2;
	int offset;// from begin struct to vertices
	float unk3;
};
struct sPspGeometryMesh
{
	int offset;
	__int16 numTriangles;
	__int16 matID;
	float unk1;
	float uvScale[2];
	float unk2[4];
	float unk3;
	char bonemap[8];
};
struct RpGeometry
{
	RwObject object;
	__int16 refCount;
	__int16 pad1;
	RpMaterialList matList;
	int pSkinPlg;
	int pad2;
	sPspGeometry msPspGeometry;
	sPspGeometryMesh msPspGeometryMesh;
};
struct CAnimBlendClumpData
{
	//CAnimBlendLink link;
	//int numFrames;
	//CVuVector* velocity2d;
	//AnimBlendFrameData* frames;
};
struct RpClump
{
	RwObject object;
	RwLinkList atomicList;
	ClumpExt ClumpExt;
	CAnimBlendClumpData* pClumpAnimDataPlugin;
};
#define RpAtomic_fromClump(ptr) ( (RpAtomic*) (((uint8_t*)ptr) - 0x1C) ) // RslElementGroupForAllElements + inElementGroupLink__inClump: link ptr - 0x1C = pAtomic*
#define RwTexture_fromDictionary(ptr) ( (RwTexture*) (((uint8_t*)ptr) - 0x8) )
struct AtomicExt
{
	__int16 modelId;
	__int16 flags;
};
struct HAnimNodeInfo
{
	char field_0;
	char field_1;
	char flags;
	char field_3;
	int field_4;
};
struct RpHAnimHierarchy
{
	int flags;
	int numNodes;
	int pCurrentAnim;
	int currentTime;
	int pNextFrame;
	int pAnimCallBack;
	int pAnimCallBackData;
	int animCallBackTime;
	int pAnimLoopCallBack;
	int pAnimLoopCallBackData;
	int pMatrixArray;
	int pMatrixArrayUnaligned;
	HAnimNodeInfo* pNodeInfo;
	int field_34;
};
struct RpAtomic
{
	RwObjectHasFrame object;
	RpGeometry* geometry;
	RpClump* clump;
	RwLLLink inElementGroupLink;
	void* renderCallBack;
	AtomicExt AtomicExt;
	RpHAnimHierarchy* pAtomicHAnimHierarchyPlugin;
	int field_30;
};
enum RwObjectType
{
	rpFRAME = 0,
	rpATOMIC = 1,
	rpCLUMP = 2,
	rpLIGHT = 3,
	rpCAMERA = 4,
	rp5 = 5,
	rpTEXDICTIONARY = 6,
	rpWORLD = 7,
	rpGEOMETRY = 8,
};
const char* GetRwObjectDescByType(int objtype)
{
	switch (objtype) {
	case rpFRAME: return "FRAME";
	case rpATOMIC: return "ATOMIC";
	case rpCLUMP: return "CLUMP";
	case rpLIGHT: return "LIGHT";
	case rpCAMERA: return "CAMERA";
	case rp5: return "reserved";
	case rpTEXDICTIONARY: return "TEXDICTIONARY";
	case rpWORLD: return "WORLD";
	case rpGEOMETRY: return "GEOMETRY";
	default: return "Unknown case";
	}
}
union uRslObjects
{
	RwObject* m_rwObject;
	RpClump* m_rpClump;
	RpAtomic* m_rpAtomic;
};
/* 478 */
struct CEntity
{
	CPlaceable CPlaceable;
	void* m_pFirstReference;
	union
	{
		struct {
			// 0x48
			uint16_t m_bDummyHasRwMatrix : 1; // dummy psp ps2
			uint16_t m_type : 3; // eEntityType
			uint16_t m_status : 5; // eEntityStatus

			// 0x49
			//uint16_t m_status : 1 <--- last bit m_status from 0x48
			uint16_t bUsesCollision : 1;      // does entity use collision
			uint16_t bCollisionProcessed : 1; // has object been processed by a ProcessEntityCollision function
			uint16_t bIsStatic : 1;           // is entity static
			uint16_t bHasContacted : 1;       // has entity processed some contact forces
			uint16_t bPedPhysics : 1;
			uint16_t bIsStuck : 1;          // is entity stuck
			uint16_t bIsInSafePosition : 1; // is entity in a collision free safe position
		};
		struct {
			uint8_t CE_flags_A;
			uint8_t CE_flags_B;
		};
	};
	uint8_t CE_flags_C;
	uint8_t CE_flags_D;
	uint8_t _CE_flags_E;
	uint8_t CE_flags_F;
	uint8_t CE_flags_G;
	uint8_t CE_flags_H;
	//RpAtomic* m_rwObject;
	uRslObjects m_urwObject; // 4b
	__int16 m_scanCode;
	__int16 m_modelIndex;
	__int16 m_modelIndex2;
	int8_t m_level : 3;
	int8_t m_area : 5;
	char m_nLastWeaponToDamage;
	void* vftable;
};
static_assert(sizeof(CEntity) == 0x60, "sizeof(CEntity)");

/* 486 */
struct CPlayerInfo
{
	CEntity* m_pPed;
	CEntity* m_pRemoteVehicle;
	char field_8[180];
	int m_nMoney;
	char pppaaaddd[28];
	int m_pHooker;
	char field_E0[24];
	int field_F8;
	char field_FC[4];
	int m_nTimeTankShotGun;
	char field_104[140];
}; // size done

/* 628 */
enum ModelInfoType
{
	MITYPE_NA = 0,
	MITYPE_SIMPLE = 1,
	MITYPE_MLO = 2,
	MITYPE_TIME = 3,
	MITYPE_WEAPON = 4,
	MITYPE_CLUMP = 5,
	MITYPE_VEHICLE = 6,
	MITYPE_PED = 7,
	MITYPE_XTRACOMPS = 8,
	MITYPE_HAND = 9,
};
enum eVehicleType
{
	VEHICLE_TYPE_CAR = 0x0,
	VEHICLE_TYPE_BOAT = 0x1,
	VEHICLE_TYPE_JETSKI = 0x2,
	VEHICLE_TYPE_TRAIN = 0x3,
	VEHICLE_TYPE_HELI = 0x4,
	VEHICLE_TYPE_PLANE = 0x5,
	VEHICLE_TYPE_BIKE = 0x6,
	VEHICLE_TYPE_FERRY = 0x7,
	VEHICLE_TYPE_BMX = 0x8,
	VEHICLE_TYPE_QUAD = 0x9,
	NUM_VEHICLE_TYPES = 0xA,
};
/* 634 */
struct __declspec(align(1)) tVehicleSampleData
{
	int m_nAccelerationSampleIndex;
	uint8_t m_nBank;
	char _field_5[3];
	int m_nHornSample;
	int32_t m_nHornFrequency;
	int32_t m_nSirenOrAlarmSample; // ?
	int32_t m_nSirenOrAlarmFrequency;
	uint8_t m_bDoorType;
};
struct CColModel;
struct CBaseModelInfo
{
	int m_unkTimers[2];
	int m_nameHashKey;
	int m_chunkMdlFile;
	char m_type;
	char m_num2dEffects;
	char ownsColModel;
	char field_13;
	CColModel* m_colModel;
	__int16 m_2dEffectsID;
	__int16 m_objectId;
	__int16 m_refCount;
	__int16 m_txdSlot;
	__int16 m_interiorGroupIndex;
	__int16 field_22;
	void* vftable_MLO;
};
struct CElementGroupModelInfo
{
	CBaseModelInfo CBaseModelInfo;
	RpClump* m_clump;
	int m_animFileIndexOrName;
};
struct CVehicleModelInfo
{
	CElementGroupModelInfo CElementGroupModelInfo;
	CRGBA m_aCurrentAvoidColours[2];
	int m_pHandlingData; // tHandlingData
	int m_pHandlingBike; // tBikeHandlingData
	int m_pHandlingFlying; // tFlyingHandlingData
	int m_pHandlingBoat; // tBoatHandlingData
	int m_pHandlingJetski; // tJetskiHandlingData
	int m_pHandling6atv; // t6atvHandlingData
	float m_normalSplay;
	eVehicleType m_vehicleType;
	float m_wheelScale;
	float m_wheelScaleRear;
	CVuVector m_positions[15];
	int m_compRules;
	int m_steerAngle___m_bikeSteerAngle;
	char m_gameName[8];
	char m_nUnk160;
	char m_nNumColourVariations;
	char m_nNumScriptColourVariations;
	char m_anColourVariationIndices[16];
	char m_anScriptColourVariationIndices[4];
	cRGB m_anLocalColoursTable[4];
	char field_183;
	CRGBA m_aCurrentColours[2];
	int m_materials1[30];
	int m_materials2[25];
	RpAtomic** m_comps__m_extras;
	int m_animFileIndexOrName;
	__int16 m_wheelId_Or_m_planeLodId_union;
	__int16 m_frequency;
	char m_numDoors;
	char m_vehicleClass;
	char m_level;
	char m_numComps;
	char m_nLastChosenColourVariation;
	char field_279[3];
	int m_nFlags;
	char field_280[4];
	tVehicleSampleData m_SampleData;
	char m_nRadioStation;
	char field_29E;
	char field_29F;
};
struct tPedColMat
{
	RpMaterial* material;
	char colindex_field_4;
	char _field_5[3];
};
struct CPedModelInfo
{
	CElementGroupModelInfo CElementGroupModelInfo;
	int animGroup;
	int pedType;
	int pedStatType;
	int carsDriveMask___m_carsCanDrive;
	CColModel* pHitColModel;
	char radio1;
	char radio2;
	char m_nLastChosenColourVariation;
	char m_nNumColourVariations;
	char m_nNumScriptColourVariations;
	char m_anColourVariationIndices[64];
	char m_anScriptColourVariationIndices[16];
	cRGB m_anLocalColoursTable[9];
	tPedColMat renderMaterials[6];
	char gameName[8];
	int field_EC;
	int field_F0;
	int field_F4;
	int field_F8;
};
struct tSample
{
	int nOffset;
	int nSize;
	int nFrequency;
};
struct __declspec(align(4)) CPool
{
	void* m_Objects; // m_entries
	unsigned __int8* m_ByteMap; // m_flags
	int m_nSize; // m_size
	int m_nFirstFree; // m_allocPtr
	char name[16];
};
struct CEscalator
{
	CVuVector m_pos0;
	CVuVector m_pos1;
	CVuVector m_pos2;
	CVuVector m_pos3;
	CMatrixAlign m_matrix;
	char m_bIsActive;
	char m_bIsMovingDown;
	char field_92[2];
	int m_stepsCount;
	float m_lowerEnd;
	float m_upperEnd;
	CVuVector m_midPoint;
	float m_radius;
	void* _0_m_pSteps;
	void* _1_m_pSteps;
	void* _2_m_pSteps;
	void* _3_m_pSteps;
	void* _4_m_pSteps;
	void* _5_m_pSteps;
	void* _6_m_pSteps;
	void* _7_m_pSteps;
	void* _8_m_pSteps;
	void* _9_m_pSteps;
	void* _10_m_pSteps;
	void* _11_m_pSteps;
	void* _12_m_pSteps;
	void* _13_m_pSteps;
	void* _14_m_pSteps;
	void* _15_m_pSteps;
	void* _16_m_pSteps;
	void* _17_m_pSteps;
	void* _18_m_pSteps;
	void* _19_m_pSteps;
	void* _20_m_pSteps;
	void* _21_m_pSteps;
	void* _22_m_pSteps;
	void* _23_m_pSteps;
	char field_114[43];
	char field_13F;
};
struct CSphere
{
	//CVector center;
	float x, y, z;
	float radius;
};
struct CBox
{
	CVuVector min;
	CVuVector max;
};
struct CColModel
{
	CSphere boundingSphere;
	CBox boundingBox;
	unsigned __int16 numBoxes;
	unsigned __int16 numTriangles;
	unsigned char numSpheres;
	unsigned char numLines;
	unsigned char numTriBBoxes;
	char level__colStoreId;
	//CColSphere* spheres;
	//CColLine* lines;
	//CColBox* boxes;
	//CColTriBBox* triBBoxes;
	//CompressedVector* vertices;
	//CColTriangle* triangles;
	int spheres;
	int lines;
	int boxes;
	int triBBoxes;
	int vertices;
	int triangles;
};
struct CStreamingInfo
{
	CStreamingInfo* m_next;
	CStreamingInfo* m_prev;
	char m_loadState;
	char m_flags;
	__int16 m_nextID;
	int m_position;
	int m_size;
};
struct tCombatMove
{
	char field_0[32];
	void* ptr_field_20;
	void* ptr_field_24;
	__int16 m_nDelta;
	char m_nFlags;
	char field_2B;
	char flags_field_2C;
	char field_2D[6];
	char name[11];
	char field_3E;
	char field_3F;
};

//#pragma pack(push, 1)
class CCombatMoveData_A_A // what about CCombatMove_B_A CCombatStat_B_A ??
{
public:
	uint8_t field_0;
	uint8_t field_1;
	uint8_t field_2;
	uint8_t field_3;
};
static_assert(sizeof(CCombatMoveData_A_A) == 4, "sizeof(CCombatMoveData_A_A) == 4");

class CCombatMoveData_A
{
public:
	CCombatMoveData_A_A** m_aArr; // 4 ptr to pointers (16b) [p1,p2,p3,p4]
	int32_t m_nCount; // 4
};
static_assert(sizeof(CCombatMoveData_A) == 0x08 - (4) + (sizeof(void*)), "sizeof(CCombatMoveData_A) == 0x08");

class CCombatMove_A_A
{
public:
	uint8_t field_0;
	uint8_t field_1;
	uint8_t field_2;
	uint8_t m_nSpeedMin;
	uint8_t m_nSpeedMax;
	uint8_t field_5;
	uint8_t field_6;
	uint8_t field_7;
};
static_assert(sizeof(CCombatMove_A_A) == 0x08, "sizeof(CCombatMove_A_A) == 0x08");

class CCombatMove_A_B // what about CCombatMove_B_A CCombatStat_B_A CCombatMoveData_A_A // recheck probably int32
{
public:
	uint8_t field_0;
	uint8_t field_1;
	uint8_t field_2;
	uint8_t field_3;
};
static_assert(sizeof(CCombatMove_A_B) == 4, "sizeof(CCombatMove_A_B) == 4");

class CCombatMove_A //CCombatMoveWeaponData ?? // sub_881E290
{
public:
	CCombatMove_A_A* m_aArr_A;
	uint8_t field_4[4]; // what about CCombatMoveData_B_A
	uint64_t m_nWeaponsMask;
	CCombatMove_A_B* m_aArr_B; // CCombatStat_B_A? CCombatMoveData_A_A?
	uint8_t m_aMovesIndices[12]; // m_aSpecialMove ?
};
static_assert(sizeof(CCombatMove_A) == 0x20 -(4*2)+(sizeof(void*)*2), "sizeof(CCombatMove_A) == 0x20");

class CCombatMove_B_A // what about CCombatStat_B_A // recheck probably int32
{
public:
	uint8_t field_0[4];
};

class CCombatMove_B // sub_881E1C0
{
public:
	int32_t field_0;
	int32_t field_4;
	CCombatMove_B_A* m_aArr;
	uint8_t field_C;
	uint8_t m_nCount;
	uint8_t field_E[10];
};
static_assert(sizeof(CCombatMove_B) == 0x18 - (4) + (sizeof(void*)), "sizeof(CCombatMove_B) == 0x18");

class CCombatMove
{
public:
	uint8_t field_0[16];
	CVuVector vec_field_10;
	CCombatMove_A* m_aArr_A;
	CCombatMove_B* m_aArr_B;
	int16_t m_nDelta;

	// Flags A
	uint8_t b2A_1 : 1;
	uint8_t b2A_2 : 1;
	uint8_t b2A_4 : 1;
	uint8_t b2A_8 : 1;
	uint8_t b2A_10 : 1;
	uint8_t b2A_20 : 1;
	uint8_t b2A_40 : 1;
	uint8_t b2A_80 : 1;

	// Flags B // recheck
	uint8_t b2B_1 : 1;
	uint8_t b2B_2 : 1;
	uint8_t b2B_4 : 1;
	uint8_t b2B_8 : 1;
	uint8_t b2B_10 : 1;
	uint8_t b2B_20 : 1;
	uint8_t b2B_40 : 1;
	uint8_t b2B_80 : 1;

	// Flags C
	uint8_t b2C_1 : 1;
	uint8_t b2C_2 : 1;
	uint8_t b2C_4 : 1;
	uint8_t b2C_8 : 1;
	uint8_t b2C_10 : 1;
	uint8_t b2C_20 : 1;
	uint8_t b2C_40 : 1;
	uint8_t b2C_80 : 1;

	// Flags D // recheck
	uint8_t b2D_1 : 1;
	uint8_t b2D_2 : 1;
	uint8_t b2D_4 : 1;
	uint8_t b2D_8 : 1;
	uint8_t b2D_10 : 1;
	uint8_t b2D_20 : 1;
	uint8_t b2D_40 : 1;
	uint8_t b2D_80 : 1;

	uint8_t field_2E;
	uint8_t m_nCount_B;
	uint8_t m_nCount_A;
	uint8_t field_31;
	uint8_t field_32;
	char m_name[12];
	uint8_t field_3F;
};
static_assert(sizeof(CCombatMove) == 0x40 - (4 * 2) + (sizeof(void*) * 2), "sizeof(CCombatMove) == 0x40");

class CCombatMoveData
{
public:
	CCombatMove* m_aMoves;
	int32_t m_nMoveCount; // 104 // 0x68
};

class CCombatMoveData_B_A
{
public:
	uint8_t field_0[32]; // 32 =  0x6A0 / 0x35
};

class CCombatMoveData_B
{
public:
	CCombatMoveData_B_A* m_aArr;
	int32_t m_nCount; // 53 // 0x35
};

class CCombatMoves
{
public:
    CCombatMoveData_A m_DataA;   // 0x04
    CCombatMoveData m_MovesData; // 0x68
    CCombatMoveData_B m_DataB;   // 0x35
    CEntity* m_pEntity;
    uint8_t field_1C[12];

    static void Initialise(const char* pFileName);
};
static_assert(sizeof(CCombatMoves) == 0x28-(4*4)+(sizeof(void*)*4), "sizeof(CCombatMoves) == 0x28");


class CCombatStat_A
{
public:
	float field_0[2];
	uint8_t field_8[8];
};
static_assert(sizeof(CCombatStat_A) == 0x10, "sizeof(CCombatStat_A) == 0x10");

class CCombatStat_B_A // recheck, guessed by unk_973E36C size 4 to adhesiveLimitTable, probably int32
{
public:
	uint8_t field_8[4];
};
static_assert(sizeof(CCombatStat_B_A) == 0x4, "sizeof(CCombatStat_B_A) == 0x4");

class CCombatStat_B
{
public:
	int32_t field_0; // unk mem trash, probably runtime pointer
	CCombatStat_B_A* m_pData; // guessed ptr to block 4b, or pInt32
};
static_assert(sizeof(CCombatStat_B) == 0x8 - (4) + (sizeof(void*)), "sizeof(CCombatStat_B) == 0x8");

class CCombatStat
{
public:
	int32_t m_ePedStat; // NUM_PEDSTATS = 42
	int8_t field_4;
	uint8_t m_nCount_A;
	uint8_t field_6[2]; // pad?
	CCombatStat_A* m_aArr_A;
	CCombatStat_B* m_aArr_B;
	uint8_t m_nCount_B;
	uint8_t field_11[3]; // pad?
	int32_t field_14;
	int32_t field_18;
	int32_t field_1C;
	int32_t field_20;
	int32_t field_24;
	int32_t field_28;


};
static_assert(sizeof(CCombatStat) == 0x2C - (4 * 2) + (sizeof(void*) * 2), "sizeof(CCombatStat) == 0x2C");

class CCombatStats
{
public:
	CCombatStat* m_aStats;
	int16_t m_nNumStats; // 3
	uint8_t field_6[2]; // pad
};
static_assert(sizeof(CCombatStats) == 0x8 - (4) + (sizeof(void*)), "sizeof(CCombatStats) == 0x8");
//#pragma pack(pop)


//=================================================================================================== POOLS
#define CPools_ms_pPtrNodePool ((CPool*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BADEF0))) // 12
#define CPools_ms_pEntryInfoNodePool ((CPool*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BADEF4))) // 20
#define CPools_ms_pPedPool ((CPool*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BADEF8))) // 3344
#define CPools_ms_pVehiclePool ((CPool*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BADEFC))) // 2080
#define CPools_ms_pBuildingPool ((CPool*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BADF00))) // 96
#define CPools_ms_pTreadablePool ((CPool*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BADF04))) // 96
#define CPools_ms_pObjectPool ((CPool*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BADF08))) // 544
#define CPools_ms_pEmpirePool ((CPool*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BADF0C))) // 352
#define CPools_ms_pDummyPool ((CPool*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BADF10))) // 96
#define CPools_ms_pAudioScriptObjectPool ((CPool*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BADF14))) // 48
#define CTexListStore_ms_pTexListPool ((CPool*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BB1260))) // 28
#define CColStore_ms_pColPool ((CPool*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BA9E50))) // 72

#define POOLFLAG_ID 0x7F
#define POOLFLAG_ISFREE 0x80
// get entity by pool handle
inline void* CPools_GetAt(CPool* p, int32_t h, int32_t maxe) { return (h == -1) ? null : ((uint8_t*)PSPPOINTER(p->m_ByteMap))[h >> 8] == (h & 0xFF) ? &((uint8_t*)PSPPOINTER(p->m_Objects))[(h >> 8) * maxe] : null; }
// get entity by array index (slot)
inline void* CPools_GetSlot(CPool* p, int32_t i, int32_t maxentsize) { return p ? (void*)(PSPPOINTER(p->m_Objects) + (i * maxentsize)) : null; }
// index (number object in pool (array index))
inline int CPools_GetJustIndex(CPool* p, void* pE, int32_t maxe) { return pE ? (((uintptr_t)pE) - ((uintptr_t)PSPPOINTER(p->m_Objects))) / maxe : 0; }
// index (pool handle)
inline int CPools_GetIndex(CPool* p, void* pE, int32_t maxe) { int i = CPools_GetJustIndex(p, pE, maxe); return ((uint8_t*)PSPPOINTER(p->m_ByteMap))[i] + (i << 8); }
// is slot free
inline bool CPools_GetSlotIsFree(CPool* p, int32_t i) { return !!(((uint8_t*)PSPPOINTER(p->m_ByteMap))[i] & POOLFLAG_ISFREE); }


#define CWorld_Players ((uint8_t*)IDATRANSLATE(0x08BDE4B0))
#define CWorld_PlayerInFocus ((*(uint8_t*)IDATRANSLATE(0x08BB3BD8)))
#define CPad_Pads ((CPad*)IDATRANSLATE(0x08BDE610))
#define FrontEndMenuManager ((uint8_t*)IDATRANSLATE(0x08BC9100))
#define FrontEndMenuManagerSettings ((uint8_t*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BB3454)))
#define TheRadar ((uint8_t*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BB343C)))
#define TheHud ((uint8_t*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BB3438)))
#define gpThePaths ((uint8_t*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BADB40)))
#define CustomSoundTrack ((uint8_t*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BB3468)))
#define fontdef ((uint8_t*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BB2510)))
#define gpFightMoves ((uint8_t*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BAA5B0)))
#define gpFightStats ((uint8_t*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BAB230)))

// MP
#define cAdhoc_mspInst ((uint8_t*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BB344C)))
#define cLobby_mspInst ((uint8_t*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BB3458)))
#define cPeerManager_mspInst ((uint8_t*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x08BB3450)))
#define TheMPGame ((uint8_t*)IDATRANSLATE(0x08BC8FC0))
#define cNetSession_mspInst ((uint8_t*)PSPPOINTER(*(uintptr_t**)IDATRANSLATE(0x8BC9024)))

#define CModelInfo_ms_modelInfoPtrs ((CBaseModelInfo**)IDATRANSLATE(*(uintptr_t**)IDATRANSLATE(0x08BB1D78)))
#define CModelInfo_msNumModelInfos (*(uint32_t*)IDATRANSLATE(0x08BB3B48)) // ITS NUM, NOT POINTER!!!!
inline CBaseModelInfo* GetModelInfo(int index) { return EMUPOINTER<CBaseModelInfo*>(CModelInfo_ms_modelInfoPtrs[index]); }
//int GetEntityType(CEntity* pEntity) { int m_type = ((pEntity->_CE_flags_E >> 1) & 0x07); return m_type; }
//void SetEntityType(CEntity* pEntity, int type) { pEntity->_CE_flags_E &= ~(0x07 << 1); pEntity->_CE_flags_E |= (type & 0x07) << 1; }
//int GetEntityStatus(CEntity* pEntity) { int m_status = ((pEntity->_CE_flags_E >> 4) & 0x0F) | ((pEntity->CE_flags_F & 0x01) << 4); return m_status; }
//void SetEntityStatus(CEntity* pEntity, int st)
//{
//	pEntity->_CE_flags_E &= ~(0x0F << 4); pEntity->_CE_flags_E |= (st & 0x0F) << 4; pEntity->CE_flags_F &= ~0x01; pEntity->CE_flags_F |= (st >> 4) & 0x01;
//}
int GetEntityType(CEntity* pEntity) { return pEntity->m_type; }
void SetEntityType(CEntity* pEntity, int type) { pEntity->m_type = type; }
int GetEntityStatus(CEntity* pEntity) { return pEntity->m_status; }
void SetEntityStatus(CEntity* pEntity, int st) { pEntity->m_status = st; }
const char* GetEntityStatusStr(CEntity* pEntity) {
	static const char* status[] = {
	"STATUS_PLAYER",
	"STATUS_PLAYER_PLAYBACKFROMBUFFER",
	"STATUS_SIMPLE",
	"STATUS_PHYSICS",
	"STATUS_ABANDONED",
	"STATUS_WRECKED",
	"STATUS_TRAIN_MOVING",
	"STATUS_TRAIN_NOT_MOVING",
	"STATUS_FERRY_MOVING",
	"STATUS_FERRY_NOT_MOVING",
	"STATUS_HELI",
	"STATUS_PLANE",
	"STATUS_PLAYER_REMOTE",
	"STATUS_PLAYER_DISABLED",
	"STATUS_GHOST",
	};
	return status[GetEntityStatus(pEntity)];
}
void TeleportEntity(CEntity* pE, CVuVector pos, bool updrw = true)
{
	//if (pE) { pE->CPlaceable.m_pMat.pos.x = pos.x; pE->CPlaceable.m_pMat.pos.y = pos.y; pE->CPlaceable.m_pMat.pos.z = pos.z; }
	if (pE) { SetCVector4VU(&pE->CPlaceable.m_pMat.pos, &pos); }
	if (pE && updrw && pE->CPlaceable.m_pMat.m_pRwMat) { SetRWV3D(&pE->CPlaceable.m_pMat.m_pRwMat->pos, &pos); } // todo update rw stuff
}
//inline CBaseModelInfo* GetModelInfo(int index) { return EMUPOINTER<CBaseModelInfo*>(CModelInfo_ms_modelInfoPtrs[index]); }
CEntity* FindPlayerPed() { return EMUPOINTER<CEntity*>(((CPlayerInfo*)CWorld_Players)[CWorld_PlayerInFocus].m_pPed); }
//CEntity* FindPlayerVehicle() {
//	CPed* pPed = EMUPOINTER<CPed*>(((CPlayerInfo*)CWorld_Players)[CWorld_PlayerInFocus].m_pPed);
//	return EMUPOINTER<CVehicle*>(pPed ? pPed->m_pMyVehicle : null);
//}
//CVector FindPlayerPos() { return FindPlayerPed() ? (*(CVuVector*)&FindPlayerPed()->CPed.CPhysical.CEntity.CPlaceable.m_pMat.pos) : CVector{ 0, 0, 0 }; }
//CVector FindPlayerMenuTarget() {
//	CVuVector pos = { 0, 0, 0 };
//	for (int i = 0; i < 75; i++) { // NUMRADARBLIPS
//		if (TheRadar->ms_RadarTrace[i].m_eRadarSprite == eRadarSprite::RADAR_SPRITE_MP_OBJECTIVE) { pos = TheRadar->ms_RadarTrace[i].m_vecPos; break; }
//	}
//	return { pos.x, pos.y, (pos.z == 0.0f && pos.x != 0.0f && pos.y != 0.0f) ? 12.0f : pos.z };
//}

class ModelInfoExt
{
public:
	bool inited;
	int index;
	uint32_t hash;
	std::string name; // br
	//---EXT
	//std::vector<CColModel*> allcolls; // ld steps

	static std::vector<ModelInfoExt> modelInfoExt;
	static void Init(const char* path)
	{
		std::vector<std::string> rows = FileReadAllLines(path);
		int max_index = -1;
		for (const auto& row : rows)
		{
			if (row.empty()) continue;
			int index;
			std::istringstream iss(row);
			char comma;
			if (iss >> index >> comma)
				if (index > max_index)
					max_index = index;
		}
		if (max_index >= 0)
			modelInfoExt.resize(max_index + 1);
		for (const auto& row : rows)
		{
			if (row.empty()) continue;
			int index;
			uint32_t hash;
			std::string name;
			std::istringstream iss(row);
			char comma;
			if (iss >> index >> comma >> std::hex >> hash >> comma >> name)
			{
				if (index >= 0 && index < modelInfoExt.size())
				{
					modelInfoExt[index].inited = true;
					modelInfoExt[index].index = index;
					modelInfoExt[index].hash = hash;
					modelInfoExt[index].name = name;
				}
				else
					throw std::out_of_range("Invalid index in ModelInfoExt data");
			}
		}

		printf("ModelInfoExt: total %zu\n", modelInfoExt.size());
	}
};
std::vector<ModelInfoExt> ModelInfoExt::modelInfoExt;
ModelInfoExt* GetModelInfoExt(int mi) { return &ModelInfoExt::modelInfoExt[mi]; }

void UpdPad()
{
	bool w = BTN('W');
	bool s = BTN('S');
	bool a = BTN('A');
	bool d = BTN('D');
	//bool esc = BTN(VK_ESCAPE); // used by ppsspp
	bool esc = BTN('R');

	int nPad = 0;
	CPad_Pads[nPad].NewState.DPadUp = w ? 0xFF : 0;
	CPad_Pads[nPad].NewState.DPadDown = s ? 0xFF : 0;
	CPad_Pads[nPad].NewState.DPadLeft = a ? 0xFF : 0;
	CPad_Pads[nPad].NewState.DPadRight = d ? 0xFF : 0;
	CPad_Pads[nPad].NewState.Start = esc ? 0xFF : 0;

	CPad_Pads[nPad].OldState.DPadUp = w ? 0xFF : 0;
	CPad_Pads[nPad].OldState.DPadDown = s ? 0xFF : 0;
	CPad_Pads[nPad].OldState.DPadLeft = a ? 0xFF : 0;
	CPad_Pads[nPad].OldState.DPadRight = d ? 0xFF : 0;
	CPad_Pads[nPad].OldState.Start = esc ? 0xFF : 0;

	int* pUpdJal = EMUPOINTER<int*>(0x0898B45C);
	*pUpdJal = 0; // disable pad update, todo reset recompiler cache?
}

typedef int8_t tMacAddr[6];
struct tAdhocPeerData { // old tPeerData, todo put in Adhoc.h
	tMacAddr macAddr;
	int16_t nSelectedPeerModelID;
	int16_t nTeamID; // eGameTeam
};
struct tListenAddr {
	tMacAddr mac;
	int16_t port; // uint16  pckt_info_peer ctor -1
};
struct tLobbyRemotePeer {
	tListenAddr peerAddr;
	int16_t nTeamID; // eGameTeam  old nGangID   recheck!!
};
struct tLobbyRemoteInfo { // old tMatchingEntry
	union
	{
		struct
		{
			tLobbyRemotePeer m_nSelfAddr;
			tAdhocPeerData m_nPeersConnInfo[7]; // players in lobby (6 rows, 7th dont see lobby) // slot 1 free, bug?
			int32_t m_GameType; // eGameType
			int32_t m_GameLocation; // eGameLocation
			int32_t m_nScoreLimit;
			int32_t m_nScoreCTFLimit;
			// etc... 136
		};
		char pad[136];
	};
};
struct tAdhocPlayerData {
	tMacAddr m_PlayerMacAddr;
	char m_szPlayerNickname[128];
};
struct tAdhocMatchingData {
	int32_t nState; // eMatchingDataState
	tMacAddr addr;
	int8_t padA[2];
	tLobbyRemoteInfo entry;
	int32_t nUnkCount;
};
static_assert(sizeof(tAdhocMatchingData) == 152, "tAdhocMatchingData");
#pragma pack(pop) //-----------------------------------------------------------------------------------------------------------------------------------------

class CData
{
public:
	std::vector<std::string> m_strings;

	void Add(const char* szString) {
		if (szString != nullptr)
			m_strings.push_back(std::string(szString));
	}

	bool Store(const char* szPath) {
		if (szPath == nullptr)
			return false;
		std::ofstream file(szPath);
		if (!file.is_open())
			return false;
		for (const auto& str : m_strings) {
			file << str << '\n';
		}
		file.close();
		return true;
	}

	bool Restore(const char* szPath)
	{
		if (szPath == nullptr)
			return false;
		std::ifstream file(szPath);
		if (!file.is_open())
			return false;
		m_strings.clear();
		std::string line;
		while (std::getline(file, line)) {
			m_strings.push_back(line);
		}
		file.close();
		return true;
	}
	size_t GetCount() const { return m_strings.size(); }
	void Reset() { m_strings.clear(); }
	const std::string& GetString(size_t index) const
	{
		static std::string empty;
		if (index < m_strings.size())
			return m_strings[index];
		return empty;
	}
};

CData channel1;
CData channel2;

void PrintIndent(int indent) { for (int i = 0; i < indent; ++i) putchar(' '); }
void PrintMac(const tMacAddr& mac) {
	printf("%02X:%02X:%02X:%02X:%02X:%02X",
		(uint8_t)mac[0], (uint8_t)mac[1], (uint8_t)mac[2],
		(uint8_t)mac[3], (uint8_t)mac[4], (uint8_t)mac[5]);
}
void PrintMacLine(int indent, const char* label, const tMacAddr& mac) {
	PrintIndent(indent);
	printf("%s: ", label);
	PrintMac(mac);
	printf("\n");
}
void PrintStringSafe(int indent, const char* label, const char* src, int maxlen) {
	char buf[256];
	size_t len = (maxlen < sizeof(buf) - 1) ? maxlen : sizeof(buf) - 1;
	memcpy(buf, src, len);
	buf[len] = '\0';
	buf[sizeof(buf) - 1] = '\0';
	PrintIndent(indent);
	printf("%s: \"%s\"\n", label, buf);
}

class sReadSyncStream
{
public:
	uint8_t sequence;
	uint8_t m_pad1[3];
	uint32_t m_pBuffer;
	uint32_t m_pBufferEnd;
};

void* pMon = nil;
void UpdateMon()
{
	sReadSyncStream* pStream = (sReadSyncStream*)pMon;
	uintptr_t m_pBuffer = EMUPOINTER<uintptr_t>(pStream->m_pBuffer);
	uintptr_t m_pBufferEnd = EMUPOINTER<uintptr_t>(pStream->m_pBufferEnd);

	system("cls");
	std::string packethex;
	DataToHexString(10, m_pBuffer, (uint8_t*)m_pBuffer, (m_pBufferEnd - m_pBuffer), &packethex);
	printf("%s\n\n", packethex.c_str());
}

void MakeIDCMLO()
{
	FILE* file = fopen("C:\\MLOPSPIDC.txt", "w");
	for (int32_t i = 0; i < CModelInfo_msNumModelInfos; i++) {
		uint32_t pMlo = (uint32_t)CModelInfo_ms_modelInfoPtrs[i]; // ppsspp
		CBaseModelInfo* modelInfo = GetModelInfo(i);
		ModelInfoExt* pInfoEx = GetModelInfoExt(i);
		if (!modelInfo) continue;

		const char* pSzType = "";
		switch (modelInfo->m_type)
		{
			case MITYPE_SIMPLE:
			{
				pSzType = "CSimpleModelInfo";
				break;
			}
			case MITYPE_MLO:
			{
				pSzType = "CMloModelInfo";
				break;
			}
			case MITYPE_TIME:
			{
				pSzType = "CTimeModelInfo";
				break;
			}
			case MITYPE_WEAPON:
			{
				pSzType = "CWeaponModelInfo";
				break;
			}
			case MITYPE_CLUMP:
			{
				pSzType = "CElementGroupModelInfo"; // CClumpModelInfo
				break;
			}
			case MITYPE_VEHICLE:
			{
				pSzType = "CVehicleModelInfo";
				break;
			}
			case MITYPE_PED:
			{
				pSzType = "CPedModelInfo";
				break;
			}

			default:
			case MITYPE_NA:
			case MITYPE_XTRACOMPS:
			case MITYPE_HAND:
			{
				assert("false modelinfo");
				break;
			}
		}
		char buff[256];
		//sprintf(buff, "SetType(%d, \"%s\");set_name(%d, form(\"Obj_0x%X\", 0x08BB1DA6), SN_AUTO);", pMlo, pSzType, pMlo);
		sprintf(buff, "SetType(0x%X, \"%s\");set_name(0x%X, \"_%d__%s__%s\", SN_AUTO);",
			pMlo, pSzType, pMlo, i, ClearStr(pInfoEx->name, "+-").c_str(), pSzType);
		fprintf(file, "%s\n", buff);

	}
	fprintf(file, "Message(\"IDC Done\\n\");\n");
	fclose(file);
	printf("MLO DUMPED!\n");
}

void GEN_COMMENT(FILE* file, uint32_t pointerdata, const char* szComment, int type = 0)
{
	char* buff = (char*)malloc(512);
	sprintf(buff, "set_cmt(0x%X, \"%s\", %d);", pointerdata, szComment, type);
	fprintf(file, "%s\n", buff);
	free(buff);
}

// альтернативный способ от GEN_FIX_OFFSET(ставил на каждий елемент тип и групировал MakeArray) можно сразу так
void GEN_ARRAY(FILE* file, uint32_t pointerdata, const char* szType = "CCombatMoveData_A_A *CCombatMoveData_A_A_aArr[4]")
{
	//SetType(0x95DAA20, "CCombatMoveData_A_A *CCombatMoveData_A_A_aArr[4];");
	char* buff = (char*)malloc(512);
	sprintf(buff, "SetType(0x%X, \"%s\");", pointerdata, szType);
	fprintf(file, "%s\n", buff);
	free(buff);
}


// MakeArray сбрасывает имя на stru_XXXXXXXX
void GEN_FIX_OFFSET(FILE* file, uint32_t pointerdata, const char* szType, const char* szName, bool typeOnly = false, int arraysize = 0, bool nameOnly = false)
{
	char* buff = (char*)malloc(512);
	if (arraysize > 0)
		sprintf(buff, "MakeArray(0x%X, %d);", pointerdata, arraysize); // kek need before define each element as type
	else
	{
		if (typeOnly)
			sprintf(buff, "SetType(0x%X, \"%s\");", pointerdata, szType);
		else if (nameOnly)
			sprintf(buff, "set_name(0x%X, \"%s\", SN_AUTO);", pointerdata, ClearStr(szName, "+-").c_str());
		else
			sprintf(buff, "SetType(0x%X, \"%s\");set_name(0x%X, \"%s\", SN_AUTO);",
				/*TYPE*/pointerdata, szType,  /*NAME*/ pointerdata, ClearStr(szName, "+-").c_str());
	}
	if(file)
		fprintf(file, "%s\n", buff);
	free(buff);
}

// TODO
void Fix_RwObjectTyped(FILE* file, RwObject* tex, const char* szName, int type)
{
	char* buff = (char*)malloc(512);
	if (type == 0) { // we RwTexture
		RwTexture* rt = EMUPOINTER<RwTexture*>(tex);
		// self fix
		const char* pSzType = "RwTexture";
		sprintf(buff, "%s_%s", szName, pSzType);
		GEN_FIX_OFFSET(file, (uint32_t)tex, pSzType, buff);

		// fix raster
		if (rt->raster) {
			Fix_RwObjectTyped(file, (RwObject*)rt->raster, szName, 1);
		}

		// fix dict (need?)

	}
	else if (type == 1) { // we RwRaster
		//RwRaster* rr = EMUPOINTER<RwRaster*>(tex);
		// self fix
		const char* pSzType = "RwRaster";
		sprintf(buff, "%s_%s", szName, pSzType);
		GEN_FIX_OFFSET(file, (uint32_t)tex, pSzType, buff);

		// display list
		// data
		int* data = OFFSET(EMUPOINTER<int*>(tex), 0x4, int*);
		if (*data) {
			sprintf(buff, "%s_%s_data", szName, pSzType);
			GEN_FIX_OFFSET(file, (uint32_t)*data, nil, buff, false, 0, true);
		}
	}
	free(buff);
}

// TODO
void Fix_RpMaterial(FILE* file, RpMaterial* material, const char* szName = NULL)
{
	// fix self
	char buff[256];
	const char* pSzType = "RpMaterial";
	sprintf(buff, "%s_%s", szName, pSzType);
	GEN_FIX_OFFSET(file, (uint32_t)material, pSzType, buff);

	// fix fields
}

/// arg object fake psp pointer non dll space
void Fix_RwObject(FILE* file, RwObject* object, const char* szName = NULL, bool typeOnly = false)
{
	char* buff = (char*)malloc(512);
	RwObject* realobject = EMUPOINTER<RwObject*>(object);
	if (realobject->type == rpATOMIC) {
		RpAtomic* atomic = (RpAtomic*)realobject;
		printf("fix RpAtomic\n");

		//---------------------- obj
		// self fix
		const char* pSzType = "RpAtomic";
		sprintf(buff, "%s_%s", szName, pSzType);
		GEN_FIX_OFFSET(file, (uint32_t)object, pSzType, buff);

		//Fix_RwObject // object.parent
		if (atomic->object.object.parent) {
			Fix_RwObject(file, (RwObject*)atomic->object.object.parent, szName, typeOnly);
		}

		// todo lFrame

		//-------------------------------

		if (atomic->geometry) {
			Fix_RwObject(file, (RwObject*)atomic->geometry, szName, typeOnly);
		}
		//RpGeometry* geo = EMUPOINTER<RpGeometry*>(atomic->geometry);

		// clump disabled recursion loop owner
		//if (atomic->clump) {
		//	Fix_RwObject(file, (RwObject*)atomic->clump, szName, true); // not rename
		//}

		// pAtomicHAnimHierarchyPlugin
		if (atomic->pAtomicHAnimHierarchyPlugin) {
			RpHAnimHierarchy* pAtomicHAnimHierarchyPlugin = EMUPOINTER<RpHAnimHierarchy*>(atomic->pAtomicHAnimHierarchyPlugin);

			// self
			const char* pSzType = "RpHAnimHierarchy";
			sprintf(buff, "%s_%s", szName, pSzType);
			GEN_FIX_OFFSET(file, (uint32_t)atomic->pAtomicHAnimHierarchyPlugin, pSzType, buff);

			// pCurrentAnim
			if (pAtomicHAnimHierarchyPlugin->pCurrentAnim) {
				// self
				const char* pSzType = "RslTAnimAnimation";
				sprintf(buff, "%s_%s", szName, pSzType);
				GEN_FIX_OFFSET(file, (uint32_t)pAtomicHAnimHierarchyPlugin->pCurrentAnim, pSzType, buff);
			}

			// pNodeInfo
			if (pAtomicHAnimHierarchyPlugin->pNodeInfo) {
				// self
				const char* pSzType = "HAnimNodeInfo";
				sprintf(buff, "%s_%s", szName, pSzType);
				GEN_FIX_OFFSET(file, (uint32_t)pAtomicHAnimHierarchyPlugin->pNodeInfo, pSzType, buff);
			}
		}
	}
	else if (realobject->type == rpCLUMP) {
		RpClump* clump = (RpClump*)realobject;
		printf("fix RpClump\n");

		//---------------------- obj
		// self fix
		const char* pSzType = "RpClump";
		sprintf(buff, "%s_%s", szName, pSzType);
		GEN_FIX_OFFSET(file, (uint32_t)object, pSzType, buff);

		// Fix fields
		//Fix_RwObject // object.parent
		if (clump->object.parent) {
			Fix_RwObject(file, (RwObject*)clump->object.parent, szName, typeOnly);
		}

		// todo lFrame

		//-------------------------------


		//Fix_RwObject // for all atomics

		RwLLLink* head = &clump->atomicList.link;
		//debug("head : 0x%p\n", head); // field clump
		RpAtomic a;
		assert(((uint8_t*)&a) == ((uint8_t*)&a.inElementGroupLink - 0x1C)); // stru test

		int i = 0;
		//for (RwLinkList* link = EMUPOINTER<RwLinkList*>(clump->atomicList.link.next); link; link = EMUPOINTER<RwLinkList*>(link->link.next)) // wrong looping
		RwLLLink* psplink = head->next;
		for (RwLLLink* link = EMUPOINTER<RwLLLink*>(head->next); link != head; link = EMUPOINTER<RwLLLink*>(link->next)) // FORLIST
		{
			RpAtomic* atomic = RpAtomic_fromClump(link); // FORLIST
			RpAtomic* pspatomic = RpAtomic_fromClump(psplink); // FORLIST
			sprintf(buff, "%s_%d", szName, i);
			Fix_RwObject(file, (RwObject*)pspatomic, buff, typeOnly); // orig psp pointer (fake)
			////printf("ATOMIC!!! [%d] : 0x%p   lnk 0x%p\n", i++, atomic, link);
			////printf("atomic: 0x%p %s\n", atomic, GetRwObjectDescByType(atomic->object.object.type));
			//RpGeometry* geo = EMUPOINTER<RpGeometry*>(atomic->geometry);
			
			psplink = link->next; // or before real link upd
			++i;
		}

		// TODO!! fix all anim hier
		//fix // pClumpAnimDataPlugin
		if (clump->pClumpAnimDataPlugin) {
			//const char* pSzType = "CAnimBlendClumpData";
			const char* pSzType = "CAnimBlendElementGroupData";
			sprintf(buff, "%s_%s", szName, pSzType);
			GEN_FIX_OFFSET(file, (uint32_t)clump->pClumpAnimDataPlugin, pSzType, buff);
		}
	}
	else if (realobject->type == rpFRAME) {
		//RwFrame* frame = (RwFrame*)realobject;
		printf("fix RwFrame\n");

		// self fix
		const char* pSzType = "RwFrame";
		sprintf(buff, "%s_%s", szName, pSzType);
		GEN_FIX_OFFSET(file, (uint32_t)object, pSzType, buff);

		// todo
	}
	else if (realobject->type == rpGEOMETRY) {
		RpGeometry* geo = (RpGeometry*)realobject;
		printf("fix RpGeometry\n");

		// self fix
		const char* pSzType = "RpGeometry";
		sprintf(buff, "%s_%s", szName, pSzType);
		GEN_FIX_OFFSET(file, (uint32_t)object, pSzType, buff);


		//pSzType = "RpMaterial";
		//sprintf(buff, "%s_%s", szName, pSzType);
		//GEN_FIX_OFFSET(file, (uint32_t)object, pSzType, buff);

		RpMaterial** mats = EMUPOINTER<RpMaterial**>(geo->matList.materials);
		// arr name
		sprintf(buff, "%s_RpMaterialArr", szName);
		pSzType = "RpMaterial*";
		GEN_FIX_OFFSET(file, (uint32_t)geo->matList.materials, pSzType, buff, false, 0, false);

		for (int32_t i = 0; i < geo->matList.numMaterials; i++) {
			RpMaterial* mat = mats[i]; // fake
			if (mat) {
				//pSzType = "RpMaterial";
				//sprintf(buff, "%s_%d_%s", szName, i, pSzType);
				//GEN_FIX_OFFSET(file, (uint32_t)mat, pSzType, buff);
				sprintf(buff, "%s_RpMaterialArr_%d", szName, i);
				Fix_RpMaterial(file, mat, buff);
			}
		}

		// todo + GEN_FIX_OFFSET settype RpMaterial* before
		// its broke name array (offset_XX)
		//if(geo->matList.numMaterials)
		//	GEN_FIX_OFFSET(file, (uint32_t)geo->matList.materials, nullptr, nullptr, false, geo->matList.numMaterials, false);


		// Fix fields
		if (geo->pSkinPlg) {
			const char* pSzType = "RpSkin";
			sprintf(buff, "%s_%s", szName, pSzType);
			GEN_FIX_OFFSET(file, (uint32_t)geo->pSkinPlg, pSzType, buff);
		}

		//todo?
	}
	else if (realobject->type == rpTEXDICTIONARY) {
		RwTexDictionary* dict = (RwTexDictionary*)realobject;
		printf("fix RwTexDictionary\n");

		// self fix
		const char* pSzType = "RwTexDictionary";
		sprintf(buff, "%s_%s", szName, pSzType);
		GEN_FIX_OFFSET(file, (uint32_t)object, pSzType, buff);

		// todo fix textures
		RwLLLink* head = &dict->textures__texturesInDict.link;
		int i = 0;
		//for (RwLinkList* link = EMUPOINTER<RwLinkList*>(clump->atomicList.link.next); link; link = EMUPOINTER<RwLinkList*>(link->link.next)) // wrong looping
		RwLLLink* psplink = head->next;
		for (RwLLLink* link = EMUPOINTER<RwLLLink*>(head->next); link != head; link = EMUPOINTER<RwLLLink*>(link->next)) // FORLIST
		{
			RwTexture* tex = RwTexture_fromDictionary(link); // FORLIST
			RwTexture* psptex = RwTexture_fromDictionary(psplink); // FORLIST
			sprintf(buff, "%s_%s_%d", szName, pSzType, i);
			Fix_RwObjectTyped(file, (RwObject*)psptex, buff, 0); // orig psp pointer (fake)

			psplink = link->next; // or before real link upd
			++i;
		}

	}
	else {
		assert(false && "unimpl");
	}
	free(buff);
}

void Fix_CColModel(FILE* file, CColModel* col, const char* szName)
{
	myassert(file && col && szName);
	char* buff = (char*)malloc(512);

	// self fix
	const char* pSzType = "CColModel";
	sprintf(buff, "%s_%s", szName, pSzType);
	GEN_FIX_OFFSET(file, (uint32_t)col, pSzType, buff);

	// fix fields
	const char* pSzFmt = "%s_%s_%d";
	CColModel* realcol = EMUPOINTER<CColModel*>(col);
	if (realcol->spheres) { // +
		for (int i = 0; i < realcol->numSpheres; i++) {
			const char* pSzType = "CColSphere";
			sprintf(buff, pSzFmt, szName, pSzType, i);
			GEN_FIX_OFFSET(file, realcol->spheres + (i * 0x20), pSzType, buff);
		}
		if(realcol->numSpheres)
			GEN_FIX_OFFSET(file, (uint32_t)realcol->spheres, nullptr, nullptr, false, realcol->numSpheres, false);
	}
	if (realcol->lines) { // +
		for (int i = 0; i < realcol->numLines; i++) {
			const char* pSzType = "CColLine";
			sprintf(buff, pSzFmt, szName, pSzType, i);
			GEN_FIX_OFFSET(file, realcol->lines + (i * 0x20), pSzType, buff);
		}
		if (realcol->numLines)
			GEN_FIX_OFFSET(file, (uint32_t)realcol->lines, nullptr, nullptr, false, realcol->numLines, false);
	}
	if (realcol->boxes) { // +
		for (int i = 0; i < realcol->numBoxes; i++) {
			const char* pSzType = "CColBox";
			sprintf(buff, pSzFmt, szName, pSzType, i);
			GEN_FIX_OFFSET(file, realcol->boxes + (i * 0x30), pSzType, buff);
		}
		if (realcol->numBoxes)
			GEN_FIX_OFFSET(file, (uint32_t)realcol->boxes, nullptr, nullptr, false, realcol->numBoxes, false);
	}
	if (realcol->triBBoxes) {
		for (int i = 0; i < realcol->numTriBBoxes; i++) {
			const char* pSzType = "CColTriBBox";
			sprintf(buff, pSzFmt, szName, pSzType, i);
			GEN_FIX_OFFSET(file, realcol->triBBoxes + (i * 0x10), pSzType, buff);
		}
		if (realcol->numTriBBoxes)
			GEN_FIX_OFFSET(file, (uint32_t)realcol->triBBoxes, nullptr, nullptr, false, realcol->numTriBBoxes, false);
	}
	if (realcol->vertices) { // +
		int numtristrip = realcol->numTriangles + 2; // 2 tri 4 vert
		for (int i = 0; i < numtristrip; i++) {
			const char* pSzType = "CompressedVector";
			sprintf(buff, pSzFmt, szName, pSzType, i);
			GEN_FIX_OFFSET(file, realcol->vertices + (i * 0x6), pSzType, buff);
		}
		if (numtristrip)
			GEN_FIX_OFFSET(file, (uint32_t)realcol->vertices, nullptr, nullptr, false, numtristrip, false);
	}
	if (realcol->triangles) { // +
		for (int i = 0; i < realcol->numTriangles; i++) {
			const char* pSzType = "CColTriangle";
			sprintf(buff, pSzFmt, szName, pSzType, i);
			GEN_FIX_OFFSET(file, realcol->triangles + (i * 0x8), pSzType, buff);
		}
		if (realcol->numTriangles)
			GEN_FIX_OFFSET(file, (uint32_t)realcol->triangles, nullptr, nullptr, false, realcol->numTriangles, false);
	}
	free(buff);
}

// TODO usage FixRwObject
void Fix_CBaseModelInfo(FILE* file, CBaseModelInfo* modelInfo, ModelInfoExt* pInfoEx, int i)
{
	// FixList: CBaseModelInfo: (?m_dmaLinks, m_chunkMdlFile_clump, vftable_MLO), m_colModel
	char buff[256];
	if (modelInfo->m_colModel) {
		//const char* pSzType = "CColModel";
		//sprintf(buff, "_%d__%s__%s", i, ClearStr(pInfoEx->name, "+-").c_str(), pSzType);
		sprintf(buff, "_%d__%s", i, ClearStr(pInfoEx->name, "+-").c_str());
		Fix_CColModel(file, modelInfo->m_colModel, buff);
	}
}

// TODO fix clump
void Fix_CElementGroupModelInfo(FILE* file, CBaseModelInfo* modelInfo, ModelInfoExt* pInfoEx, int i)
{
	CElementGroupModelInfo* clumpmodelInfo = (CElementGroupModelInfo*)modelInfo;
	char buff[256];
	if (clumpmodelInfo->m_clump) {
		//const char* pSzType = "RpClump"; // RslElementGroup
		//sprintf(buff, "_%d__%s__%s", i, ClearStr(pInfoEx->name, "+-").c_str(), pSzType);
		sprintf(buff, "_%d__%s", i, ClearStr(pInfoEx->name, "+-").c_str());
		Fix_RwObject(file, (RwObject*)clumpmodelInfo->m_clump, buff);
		//GEN_FIX_OFFSET(file, (uint32_t)clumpmodelInfo->m_clump, pSzType, buff);
	}

}

void FixupMLOPATCHES()
{
	FILE* file = fopen("C:\\IDC\\MLOPSPIDCPATCHES.txt", "w");
	for (int32_t i = 0; i < CModelInfo_msNumModelInfos; i++) {
		uint32_t pMlo = (uint32_t)CModelInfo_ms_modelInfoPtrs[i]; // ppsspp
		CBaseModelInfo* modelInfo = GetModelInfo(i);
		ModelInfoExt* pInfoEx = GetModelInfoExt(i);
		if (!modelInfo) continue;

		printf("Fix_CBaseModelInfo %d\n", i);
		Fix_CBaseModelInfo(file, modelInfo, pInfoEx, i);
		switch (modelInfo->m_type)
		{
			case MITYPE_SIMPLE: // "CSimpleModelInfo"
			{
				char buff[256];
				printf("fix  m_atomics_objects\n");
				uint32_t* m_atomics_objects = OFFSET(modelInfo, 0x28, uint32_t*);
				uint8_t m_numAtomics = *OFFSET(modelInfo, 0x38, uint8_t*);
				if (m_numAtomics && *m_atomics_objects)
				{
					// self
					const char* pSzType = "RpAtomic**";
					uint32_t pointer = *m_atomics_objects;
					sprintf(buff, "_%d__%s__atomics", i, ClearStr(pInfoEx->name, "+-").c_str());
					GEN_FIX_OFFSET(file, pointer, pSzType, buff);

					RpAtomic** atomics = EMUPOINTER<RpAtomic**>(*m_atomics_objects);
					for (int j = 0; j < m_numAtomics; j++) {
						if (!atomics[j]) continue;
						const char* pSzType = "";
						sprintf(buff, "_%d_%d_%s__%s_M2", i, j, ClearStr(pInfoEx->name, "+-").c_str(), pSzType);
						Fix_RwObject(file, (RwObject*)atomics[j], buff);
					}
				}

				// related model info

				break;
			}
			case MITYPE_MLO: // "CMloModelInfo"
			{
				printf("MITYPE_CLUMP %d\n", i);
				Fix_CElementGroupModelInfo(file, modelInfo, pInfoEx, i);

				break;
			}
			case MITYPE_TIME: // "CTimeModelInfo"
			{
				break;
			}
			case MITYPE_WEAPON: // "CWeaponModelInfo"
			{
				break;
			}
			case MITYPE_CLUMP: // "CElementGroupModelInfo"
			{
				printf("MITYPE_CLUMP %d\n", i);
				Fix_CElementGroupModelInfo(file, modelInfo, pInfoEx, i);
				break;
			}
			case MITYPE_VEHICLE: // "CVehicleModelInfo"
			{
				printf("MITYPE_VEHICLE %d\n", i);
				Fix_CElementGroupModelInfo(file, modelInfo, pInfoEx, i);

				// CVehicleModelInfo: m_pHandlingData m_pHandlingBike m_pHandlingFlying m_pHandlingBoat m_pHandlingJetski m_pHandling6atv

				char buff[256];
				CVehicleModelInfo* vehmodelInfo = (CVehicleModelInfo*)modelInfo;

				if (vehmodelInfo->m_pHandlingData) {
					const char* pSzType = "tHandlingData";
					uint32_t pointer = vehmodelInfo->m_pHandlingData;
					sprintf(buff, "_%d__%s__%s", i, ClearStr(pInfoEx->name, "+-").c_str(), pSzType);
					GEN_FIX_OFFSET(file, pointer, pSzType, buff);
				}
				if (vehmodelInfo->m_pHandlingBike) {
					const char* pSzType = "tBikeHandlingData";
					uint32_t pointer = vehmodelInfo->m_pHandlingBike;
					sprintf(buff, "_%d__%s__%s", i, ClearStr(pInfoEx->name, "+-").c_str(), pSzType);
					GEN_FIX_OFFSET(file, pointer, pSzType, buff);
				}
				if (vehmodelInfo->m_pHandlingFlying) {
					const char* pSzType = "tFlyingHandlingData";
					uint32_t pointer = vehmodelInfo->m_pHandlingFlying;
					sprintf(buff, "_%d__%s__%s", i, ClearStr(pInfoEx->name, "+-").c_str(), pSzType);
					GEN_FIX_OFFSET(file, pointer, pSzType, buff);
				}
				if (vehmodelInfo->m_pHandlingBoat) {
					const char* pSzType = "tBoatHandlingData";
					uint32_t pointer = vehmodelInfo->m_pHandlingBoat;
					sprintf(buff, "_%d__%s__%s", i, ClearStr(pInfoEx->name, "+-").c_str(), pSzType);
					GEN_FIX_OFFSET(file, pointer, pSzType, buff);
				}
				if (vehmodelInfo->m_pHandlingJetski) {
					const char* pSzType = "tJetskiHandlingData";
					uint32_t pointer = vehmodelInfo->m_pHandlingJetski;
					sprintf(buff, "_%d__%s__%s", i, ClearStr(pInfoEx->name, "+-").c_str(), pSzType);
					GEN_FIX_OFFSET(file, pointer, pSzType, buff);
				}
				if (vehmodelInfo->m_pHandling6atv) {
					const char* pSzType = "t6atvHandlingData";
					uint32_t pointer = vehmodelInfo->m_pHandling6atv;
					sprintf(buff, "_%d__%s__%s", i, ClearStr(pInfoEx->name, "+-").c_str(), pSzType);
					GEN_FIX_OFFSET(file, pointer, pSzType, buff);
				}

				// disabled by fixup in CElementGroupModelInfo in clump already this materials, double renaming
				//// m_materials1
				//for (int j = 0; j < 30; j++) {
				//	if (vehmodelInfo->m_materials1[j]) {
				//		const char* pSzType = "";
				//		sprintf(buff, "_%d_%d_%s__%s", i, j, ClearStr(pInfoEx->name, "+-").c_str(), pSzType);
				//		Fix_RpMaterial(file, (RpMaterial*)vehmodelInfo->m_materials1[j], buff);
				//	}
				//}

				//// m_materials2
				//for (int j = 0; j < 25; j++) {
				//	if (vehmodelInfo->m_materials2[j]) {
				//		const char* pSzType = "";
				//		sprintf(buff, "_%d_%d_%s__%s_M1", i, j, ClearStr(pInfoEx->name, "+-").c_str(), pSzType);
				//		Fix_RpMaterial(file, (RpMaterial*)vehmodelInfo->m_materials2[j], buff);
				//	}
				//}

				printf("fix comps\n");
				RpAtomic** extras = EMUPOINTER<RpAtomic**>(vehmodelInfo->m_comps__m_extras);
				if (extras)
				{
					for (int j = 0; j < vehmodelInfo->m_numComps; j++) {
						if (!extras[j]) continue;
						const char* pSzType = "";
						sprintf(buff, "_%d_%d_%s__%s_M2", i, j, ClearStr(pInfoEx->name, "+-").c_str(), pSzType);
						Fix_RwObject(file, (RwObject*)extras[j], buff);
					}
				}
				break;
			}
			case MITYPE_PED: // "CPedModelInfo"
			{
				printf("MITYPE_PED %d\n", i);
				Fix_CElementGroupModelInfo(file, modelInfo, pInfoEx, i);

				char buff[256];
				CPedModelInfo* pedmodelInfo = (CPedModelInfo*)modelInfo;

				if (pedmodelInfo->pHitColModel) {
					//const char* pSzType = "CColModel";
					//sprintf(buff, "_%d__%s__HitCol__%s", i, ClearStr(pInfoEx->name, "+-").c_str(), pSzType);
					sprintf(buff, "_%d__%s__HitCol", i, ClearStr(pInfoEx->name, "+-").c_str());
					Fix_CColModel(file, pedmodelInfo->pHitColModel, buff);
				}

				for (int j = 0; j < 6; j++) {
					tPedColMat& renderMaterials = pedmodelInfo->renderMaterials[j];
					const char* pSzType = "RpMaterial";
					sprintf(buff, "_%d__%d__%s__%s", i, j, ClearStr(pInfoEx->name, "+-").c_str(), pSzType);
					Fix_RpMaterial(file, renderMaterials.material, buff);
				}

				break;
			}

			default:
			case MITYPE_NA:
			case MITYPE_XTRACOMPS:
			case MITYPE_HAND:
			{
				assert("false modelinfo");
				break;
			}
		}
	}

	fprintf(file, "Message(\"IDC Done\\n\");\n");
	fclose(file);
	printf("MLOPATCHES DUMPED!\n");
}

void FixupMarkers()
{
	FILE* file = fopen("C:\\IDC\\MARKERS.txt", "w");
	char buff[256];
	RpClump** carr = EMUPOINTER<RpClump**>(*EMUPOINTER<int*>(0x08BB3E5C));
	for (int i = 0; i < 9; i++) {
		if (carr[i]) {
			sprintf(buff, "_%d_marker", i);
			Fix_RwObject(file, (RwObject*)carr[i], buff);
		}
	}
	fprintf(file, "Message(\"IDC Done\\n\");\n");
	fclose(file);
	printf("FixupMarkers DUMPED!\n");
}

void FixupPools()
{
	//CPools::ms_pBuildingPool
	//CPools::ms_pTreadablePool // empty
	//CPools::ms_pDummyPool
	//CPools::ms_pEntryInfoNodePool
	//CPools::ms_pPtrNodePool

	// fixup matrix rwmat
	// entity rwobject

	FILE* file = fopen("C:\\IDC\\POOLS.txt", "w");
	char buff[256];


	for (int32_t i = CPools_ms_pBuildingPool->m_nSize - 1; i >= 0; i--)
	{
		if (CPools_GetSlotIsFree(CPools_ms_pBuildingPool, i)) { continue; }
		CEntity* e = (CEntity*)CPools_GetSlot(CPools_ms_pBuildingPool, i, 96);
		if (e)
		{
			if (e->CPlaceable.m_pMat.m_pRwMat) {
				const char* pSzType = "RwMatrix";
				sprintf(buff, "_%d_RwMatrix_CPlaceable_BuildingPool", i);
				GEN_FIX_OFFSET(file, (uint32_t)e->CPlaceable.m_pMat.m_pRwMat, pSzType, buff);
			}

			if (e->m_urwObject.m_rwObject) {
				ModelInfoExt* pInfoEx = GetModelInfoExt(e->m_modelIndex);
				sprintf(buff, "_%d__%s_BuildingPool", i, ClearStr(pInfoEx->name, "+-").c_str());
				Fix_RwObject(file, e->m_urwObject.m_rwObject, buff);
			}

		}
	}
	for (int32_t i = CPools_ms_pTreadablePool->m_nSize - 1; i >= 0; i--)
	{
		if (CPools_GetSlotIsFree(CPools_ms_pTreadablePool, i)) { continue; }
		CEntity* e = (CEntity*)CPools_GetSlot(CPools_ms_pTreadablePool, i, 96);
		if (e)
		{

		}
	}
	for (int32_t i = CPools_ms_pDummyPool->m_nSize - 1; i >= 0; i--)
	{
		if (CPools_GetSlotIsFree(CPools_ms_pDummyPool, i)) { continue; }
		CEntity* e = (CEntity*)CPools_GetSlot(CPools_ms_pDummyPool, i, 96);
		if (e)
		{

		}
	}
	for (int32_t i = CTexListStore_ms_pTexListPool->m_nSize - 1; i >= 0; i--)
	{
		//if (CPools_GetSlotIsFree(CTexListStore_ms_pTexListPool, i)) { continue; }
		uint32_t* e = (uint32_t*)CPools_GetSlot(CTexListStore_ms_pTexListPool, i, 28);
		if (e)
		{
			char* name = OFFSET(e, 0x8, char*);
			if (*e && name[0]) {

				sprintf(buff, "_%d__%s_def_txd_pool", i, name);
				Fix_RwObject(file, (RwObject*)*e, buff, false);
				//GEN_FIX_OFFSET(file, (uint32_t)*e, pSzType, buff);
			}

			//printf("%s\n", e->name);
		}
	}
	//for (int32_t i = CColStore_ms_pColPool->m_nSize - 1; i >= 0; i--)
	//{
	//	if (CPools_GetSlotIsFree(CColStore_ms_pColPool, i)) { continue; }
	//	ColDef* c = (ColDef*)CPools_GetSlot(CColStore_ms_pColPool, i, 72);
	//	if (c)
	//	{
	//		printf("col%d 0x%p  %s\n", i, c, c->name);
	//	}
	//}

	fprintf(file, "Message(\"IDC Done\\n\");\n");
	fclose(file);
	printf("FixupPools DUMPED!\n");
}

bool HasReloc(uint32_t ptr, uint8_t* dtz = nil, bool dst = false)
{
	if (!ptr)
		return false;
	if(!dtz)
		dtz = (uint8_t*)(*EMUPOINTER<int*>(0x08BB1D78)) - (0x0969AB70 - 0x0938A700); // default
	//printf("dtz 0x%p ptr 0x%p\n", dtz, ptr);
	static FILE* dtzfile = nil;
	static std::vector<uint32_t> classes(14798);
	static std::vector<uint32_t> funcs(23);
	static std::vector<uint32_t> reloc(139992);

	if (!dtzfile) {
		dtzfile = fopen("GAME.dat", "rb");
		if (!dtzfile) ExitProcess(0);
		fseek(dtzfile, 0x0056B1DC, SEEK_SET); // classes
		fread(classes.data(), sizeof(uint32_t), 14798, dtzfile);
		fseek(dtzfile, 0x00579914, SEEK_SET); // funcs
		fread(funcs.data(), sizeof(uint32_t), 23, dtzfile);
		fseek(dtzfile, 0x00579970, SEEK_SET); // reloc
		fread(reloc.data(), sizeof(uint32_t), 139992, dtzfile);
		fclose(dtzfile);
	}

	for (int i = 0; i < 139992; i++) {
		//printf("dptr 0x%p rel 0x%p mptr 0x%p\n", (dtz + reloc[i]), reloc[i], ptr);
		if (dst && ptr == *(uint32_t*)(dtz + reloc[i]))
			return true;
		if (ptr == (uint32_t)(dtz + reloc[i]))
			return true;
	}
	return false;
}

 //shrink remove data
void test()
{
	//char* buff = (char*)malloc(1024*1024*10);
	char* buff = (char*)malloc(0x6024D0*2);
	FILE* dtzfile = fopen("GAME.dat", "rb");
	int read = fread(buff, 1, 0x6024D0, dtzfile);
	printf("0x%p\n", *(int*)&buff[0x6024D0-4]);
	fclose(dtzfile);
	free(buff);
}

//void test()
//{
//	printf("[LOG] Начало функции test()\n");
//
//	// Вычисляем размер для выделения памяти
//	size_t alloc_size = 0x6024D0 * 2;
//	printf("[LOG] Выделяем память размером: 0x%zx байт\n", alloc_size);
//
//	char* buff = (char*)malloc(alloc_size);
//	if (buff == NULL) {
//		printf("[ERROR] Не удалось выделить память!\n");
//		return;
//	}
//	printf("[LOG] Память успешно выделена по адресу: %p\n", buff);
//
//	printf("[LOG] Открываем файл GAME.dat\n");
//	FILE* dtzfile = fopen("GAME.dat", "rb");
//	if (dtzfile == NULL) {
//		printf("[ERROR] Не удалось открыть файл GAME.dat!\n");
//		free(buff);
//		return;
//	}
//	printf("[LOG] Файл успешно открыт\n");
//
//	size_t read_size = 0x6024D0;
//	printf("[LOG] Читаем %zu байт из файла\n", read_size);
//	size_t bytes_read = fread(buff, 1, read_size, dtzfile);
//	printf("[LOG] Прочитано %zu байт\n", bytes_read);
//
//	if (bytes_read < read_size) {
//		printf("[WARNING] Прочитано меньше байт, чем ожидалось!\n");
//	}
//
//	// Вычисляем адрес для чтения значения
//	size_t target_offset = 0x6024D0 - 4;
//	printf("[LOG] Читаем значение по смещению: 0x%zx (адрес: %p)\n",
//		target_offset, buff + target_offset);
//
//	int value = *(int*)&buff[target_offset];
//	printf("0x%p\n", (void*)(intptr_t)value);
//	printf("[LOG] Прочитанное значение: 0x%x (десятичное: %d)\n", value, value);
//
//	printf("[LOG] Закрываем файл\n");
//	fclose(dtzfile);
//
//	printf("[LOG] Освобождаем память\n");
//	free(buff);
//
//	printf("[LOG] Конец функции test()\n");
//}
//
//void test2()
//{
//	char* buff = (char*)malloc(0x6024D0 * 2);
//
//	// Узнаем текущую директорию и путь к файлу
//	char path[256];
//	GetCurrentDirectoryA(256, path);
//	printf("Текущая директория: %s\n", path);
//	printf("Пытаемся открыть: %s\\GAME.dat\n", path);
//
//	// Проверяем существует ли файл
//	FILE* dtzfile = fopen("GAME.dat", "rb");
//	if (dtzfile == NULL) {
//		printf("Файл GAME.dat НЕ НАЙДЕН в текущей директории!\n");
//
//		// Ищем файл в директории с программой
//		char exe_path[256];
//		GetModuleFileNameA(NULL, exe_path, 256);
//		printf("Путь к EXE: %s\n", exe_path);
//		free(buff);
//		return;
//	}
//
//	// Проверяем размер файла
//	fseek(dtzfile, 0, SEEK_END);
//	long size = ftell(dtzfile);
//	fseek(dtzfile, 0, SEEK_SET);
//
//	printf("Размер файла: %ld байт (%.2f MB)\n", size, size / (1024.0 * 1024.0));
//	printf("Ожидаемый размер: 6300880 байт (6.01 MB)\n");
//
//	if (size < 6300880) {
//		printf("ФАЙЛ СЛИШКОМ МАЛЕНЬКИЙ! Нужен файл 6 МБ\n");
//		fclose(dtzfile);
//		free(buff);
//		return;
//	}
//
//	fread(buff, 1, 0x6024D0, dtzfile);
//	printf("0x%p\n", *(int*)&buff[0x6024D0 - 4]);
//
//	fclose(dtzfile);
//	free(buff);
//}

void GenRelocComs()
{
	FILE* file = fopen("C:\\COMENTS.txt", "w");
	uint8_t* dtz = (uint8_t*)(*EMUPOINTER<int*>(0x08BB1D78)) - (0x0969AB70 - 0x0938A700);
	//uint32_t* dclasses = (uint32_t*)(dtz + 0x0056B1DC); // 14798
	//uint32_t* dfuncs = (uint32_t*)(dtz + 0x00579914); // 23
	//uint32_t* dreloc = (uint32_t*)(dtz + 0x00579970); // 139992
	//printf("dtz 0x%p realdtz 0x%p   0x%p 0x%p 0x%p\n", dtz, realdtz, dclasses, dfuncs, dreloc);

	// not in ppsspp memory after shrink
	FILE* dtzfile = fopen("GAME.dat", "rb");
	if (!dtzfile) ExitProcess(0);
	fseek(dtzfile, 0x0056B1DC, SEEK_SET); // classes
	std::vector<uint32_t> classes(14798);
	fread(classes.data(), sizeof(uint32_t), 14798, dtzfile);
	fseek(dtzfile, 0x00579914, SEEK_SET); // funcs
	std::vector<uint32_t> funcs(23);
	fread(funcs.data(), sizeof(uint32_t), 23, dtzfile);
	fseek(dtzfile, 0x00579970, SEEK_SET); // reloc
	std::vector<uint32_t> reloc(139992*2);
	fread(reloc.data(), 1, 139992 * 4, dtzfile);
	fclose(dtzfile);

	for (int i = 0; i < 14798; i++) {
		GEN_COMMENT(file, (uint32_t)(dtz + classes[i]), "classes table", 0);
	}
	for (int i = 0; i < 23; i++) {
		GEN_COMMENT(file, (uint32_t)(dtz + funcs[i]), "functions table", 0);
		GEN_FIX_OFFSET(file, (uint32_t)(dtz + funcs[i]), "void*", nullptr, true, 0);
	}
	for (int i = 0; i < 139992; i++) {
		GEN_COMMENT(file, (uint32_t)(dtz + reloc[i]), "relocate table", 0);
		GEN_FIX_OFFSET(file, (uint32_t)(dtz + reloc[i]), "void*", nullptr, true, 0);
	}

	fprintf(file, "Message(\"IDC Done\\n\");\n");
	fclose(file);
	printf("GenRelocComs DUMPED!\n");
}

void FixupInter()
{
	FILE* file = fopen("C:\\IDC\\INTERS.txt", "w");
	uint8_t* dtz = (uint8_t*)(*EMUPOINTER<int*>(0x08BB1D78)) - (0x0969AB70 - 0x0938A700);
	char buff[256];

	uint32_t pointer = 0x09401360 + 4 + 4;
	for (int i = 0; i < 0x42; i++) {
		uint32_t p = *EMUPOINTER<uint32_t*>(pointer);
		const char* pSzType = "CInteriorInfo";
		sprintf(buff, "_%d__interiorinfo", i);
		GEN_FIX_OFFSET(file, p, pSzType, buff);
		pointer += 8;
	}
	fprintf(file, "Message(\"IDC Done\\n\");\n");
	fclose(file);
	printf("FixupInter DUMPED!\n");
}

void FixupStatsTypes()
{
	FILE* file = fopen("C:\\IDC\\STATSTYPES.txt", "w");
	uint8_t* dtz = (uint8_t*)(*EMUPOINTER<int*>(0x08BB1D78)) - (0x0969AB70 - 0x0938A700);
	char buff[256];

	// Stats
	uint32_t* ptr = EMUPOINTER<uint32_t*>(0x097395E0);
	for (int i = 0; i < 42; i++)
	{
		uint32_t p = ptr[i]; // fake
		char* name = OFFSET(EMUPOINTER<char*>(p), 0x1A, char*);

		const char* pSzType = "CPedStats";
		sprintf(buff, "STATS_%s", name);
		GEN_FIX_OFFSET(file, p, pSzType, buff);
	}

	// Types
	ptr = EMUPOINTER<uint32_t*>(0x0973E870);
	for (int i = 0; i < 23; i++)
	{
		uint32_t p = ptr[i]; // fake

		const char* pSzType = "CPedType";
		sprintf(buff, "_%d_pedtype", i);
		GEN_FIX_OFFSET(file, p, pSzType, buff);
	}

	fprintf(file, "Message(\"IDC Done\\n\");\n");
	fclose(file);
	printf("FixupStats DUMPED!\n");
}

void FixupEtc()
{
	// fighting x2
	// fontdef


	FILE* file = fopen("C:\\IDC\\ETC.txt", "w");
	//FILE* file = nil;
	// DTZ 0x0938A700
	uint8_t* dtz = (uint8_t*)(*EMUPOINTER<int*>(0x08BB1D78)) - (0x0969AB70 - 0x0938A700); // fake
	char buff[512];

#if 0 // streaming
	uint32_t psi = 0x096B1530;
	uint32_t ms_startLoadedList = psi + 0x9C;
	uint32_t ps = *EMUPOINTER<uint32_t*>(ms_startLoadedList);
	uint32_t ms_endLoadedList = psi + 0xA0;
	uint32_t pe = *EMUPOINTER<uint32_t*>(ms_endLoadedList);
	// end 096B15CC field ms_startLoadedList in streaming
	printf("assert %d\n", ms_startLoadedList == 0x096B15CC);

	int i = 0;
	uint32_t tps = ps;
	CStreamingInfo* rps = EMUPOINTER<CStreamingInfo*>(ps);
	while (1)
	{
		printf("i %d me 0x%p  my next 0x%p\n", i++, tps, rps->m_next);

		const char* pSzType = "CStreamingInfo";
		sprintf(buff, "_%d_LoadedList_CStreamingInfo", i);
		GEN_FIX_OFFSET(file, tps, pSzType, buff);

		tps = (uint32_t)rps->m_next;
		rps = EMUPOINTER<CStreamingInfo*>(tps);
		if (tps == ms_startLoadedList) break;
	}
#endif

#if 0 // anim
	uint32_t inst = 0x0959A720;
	uint32_t m_aAnimations = inst + 0x0001013C; // 985
	uint32_t pm_aAnimations = *EMUPOINTER<uint32_t*>(m_aAnimations);
	uint32_t m_aAnimBlocks = inst + 0x00010140; // 140
	uint32_t pm_aAnimBlocks = *EMUPOINTER<uint32_t*>(m_aAnimBlocks);
	uint32_t m_aAnimAssocGroups = inst + 0x0001014C; // 123
	uint32_t pm_aAnimAssocGroups = *EMUPOINTER<uint32_t*>(m_aAnimAssocGroups);

#if 0 // m_aAnimations->blendSequences->keyFrames
	// m_aAnimation
	uint8_t* rm_aAnimations = EMUPOINTER<uint8_t*>(pm_aAnimations);
	for (uint32_t i = 0; i < 985; i++) // 0x28 CAnimBlendTree
	{
		//sprintf(buff, "C:\\IDC\\anim\\anim_%d.idc", i);
		//printf("curr %s\n", buff);
		//FILE* file = fopen(buff, "w");
		uint8_t* curr = rm_aAnimations + (0x28 * i); // CAnimBlendTree
		uint32_t currf = pm_aAnimations + (0x28 * i); // CAnimBlendTree
		uint32_t pblendSequences = *OFFSET(curr, 0x0, uint32_t*); // CAnimBlendSequence
		char* name = OFFSET(curr, 0x4, char*);
		uint16_t numSequences = *OFFSET(curr, 0x1C, uint16_t*);

		printf("curr animtree %d/985 %s, 0x%p numSequences %d  off 0x%p\n", i, name, currf, numSequences, currf - (uint32_t)dtz);
		if (pblendSequences)
		{
			//myassert(HasReloc(OFFSET(currf, 0x0, uint32_t)));
			if (!HasReloc(OFFSET(currf, 0x0, uint32_t))) continue;

			// self
			//const char* pSzType = "CAnimBlendTree";
			//sprintf(buff, "_%d_LoadedList_CStreamingInfo", i);
			//GEN_FIX_OFFSET(file, tps, pSzType, buff);

			// blendSequences
			uint8_t* rblendSequences = EMUPOINTER<uint8_t*>(pblendSequences); // CAnimBlendSequence
			for (uint32_t j = 0; j < numSequences; j++) {
				uint32_t currSF = pblendSequences + (0xC * j);
				uint8_t* currS = rblendSequences + (0xC * j);

				const char* pSzType = "CAnimBlendSequence";
				sprintf(buff, "_%s_%d_CAnimBlendSequence", name, j);
				GEN_FIX_OFFSET(file, currSF, pSzType, buff);

				uint16_t numFrames = *OFFSET(currS, 0x2, uint16_t*);
				uint32_t keyFrames = *OFFSET(currS, 0x4, uint32_t*);
				uint8_t* rkeyFrames = EMUPOINTER<uint8_t*>(keyFrames);

				//printf("  curr seq %d 0x%p numFrames %d  off 0x%p\n", j, currSF, numFrames, keyFrames - (uint32_t)dtz);
				if (HasReloc(OFFSET(currSF, 0x4, uint32_t))) // filter out pointer fields, someone can have trash
				{
					//myassert(HasReloc(OFFSET(currSF, 0x4, uint32_t)));
					for (uint32_t k = 0; k < numFrames; k++) {
						uint32_t currKFF = keyFrames + (0xA * k);
						uint8_t* currKF = rkeyFrames + (0xA * k);

						const char* pSzType = "KeyFrame";
						sprintf(buff, "_%s_%d_CAnimBlendSequence_%d_KeyFrame", name, j, k);
						GEN_FIX_OFFSET(file, currKFF, pSzType, buff);
					}
					if (numFrames)
						GEN_FIX_OFFSET(file, keyFrames, nullptr, nullptr, false, numFrames, false);
				}
				else {
					printf("  skip curr seq %d 0x%p numFrames %d reason no in reloc table trash in memory\n", j, currSF, numFrames);
				}
			}
			if (numSequences)
				GEN_FIX_OFFSET(file, pblendSequences, nullptr, nullptr, false, numSequences, false);
		}
		else {
			printf("%s has no %p blendSequences 0x%p\n", name, pblendSequences, currf); // why
		}
		//GEN_FIX_OFFSET
		//channel1.Add(name);
		//if (name[0]) {
		//	printf("%d %s\n", i, name);
		//}
		//fprintf(file, "Message(\"IDC Done\\n\");\n");
		//fclose(file);
		//break;
	}
	//channel1.Store("C:\\IDC\\m_aAnimations_psp.txt");
	//channel1.Reset();
#endif

#if 0
	// m_aAnimBlocks
	uint8_t* rm_aAnimBlocks = EMUPOINTER<uint8_t*>(pm_aAnimBlocks);
	for (uint32_t i = 0; i < 140; i++) // 0x2C CAnimBlock
	{
		uint8_t* curr = rm_aAnimBlocks + (0x2C * i);
		char* name = OFFSET(curr, 0x0, char*);
		//channel1.Add(name);
		if (name[0]) {
			printf("%d %s\n", i, name);
		}
	}
	//channel1.Store("C:\\IDC\\m_aAnimBlocks_psp.txt");
	//channel1.Reset();
#endif

#if 1
	// m_aAnimAssocGroups
	uint8_t* rm_aAnimAssocGroups = EMUPOINTER<uint8_t*>(pm_aAnimAssocGroups);
	for (uint32_t i = 0; i < 123; i++) // 0x14 CAnimBlendAssocGroup
	{
		uint8_t* curr = rm_aAnimAssocGroups + (0x14 * i);
		uint32_t currF = pm_aAnimAssocGroups + (0x14 * i);
		uint32_t m_aAssociationArray = *OFFSET(curr, 0x4, uint32_t*);
		uint32_t numAssociations = *OFFSET(curr, 0x8, uint32_t*);

		bool rel = HasReloc(OFFSET(currF, 0x4, uint32_t));
		//if (rel)
		{
			//printf("YES assoc ok reloc\n");
			uint8_t* rm_aAssociationArray = EMUPOINTER<uint8_t*>(m_aAssociationArray);
			for (int j = 0; j < numAssociations; j++) {
				uint8_t* currAA = rm_aAssociationArray + (0x44 * j);
				uint32_t currAAF = m_aAssociationArray + (0x44 * j);


				const char* pSzType = "CAnimBlendAssociation";
				sprintf(buff, "%s_%d__%d_AnimAssocGroups_CAnimBlendAssociation", rel ? "" : "DYNAMIC_NONDTZ", i, j);
				GEN_FIX_OFFSET(file, currAAF, pSzType, buff);

				uint32_t m_iNumAnimBlendNodes = *OFFSET(currAA, 0x18, uint32_t*); // CAnimBlendNode 0x20
				uint32_t m_pAnimBlendNodes = *OFFSET(currAA, 0x1C, uint32_t*);
				uint8_t* rm_pAnimBlendNodes = EMUPOINTER<uint8_t*>(m_pAnimBlendNodes);
				for (int k = 0; k < m_iNumAnimBlendNodes; k++) {
					uint8_t* currBF = rm_pAnimBlendNodes + (0x20 * k);
					uint32_t currBFF = m_pAnimBlendNodes + (0x20 * k);

					const char* pSzType = "CAnimBlendNode";
					sprintf(buff, "%s_%d__%d_AnimAssocGroups_CAnimBlendAssociation_%d_CAnimBlendNode", rel ? "" : "DYNAMIC_NONDTZ", i, j, k);
					GEN_FIX_OFFSET(file, currBFF, pSzType, buff);
				}
				if (m_iNumAnimBlendNodes)
					GEN_FIX_OFFSET(file, m_pAnimBlendNodes, nullptr, nullptr, false, m_iNumAnimBlendNodes, false);
			}
			if (numAssociations)
				GEN_FIX_OFFSET(file, m_aAssociationArray, nullptr, nullptr, false, numAssociations, false);
		}
		//else {
		//	printf("NO in reloc\n");
		//}


		//char* name = OFFSET(curr, 0x0, char*);
		//channel1.Add(name);
		//if (name[0]) {
		//	printf("%d %s\n", i, name);
		//}
	}
#endif

#endif

	// weatherlist
#if 0
	const char* w[] = {
		"WEATHER_SUNNY",
		"WEATHER_CLOUDY",
		"WEATHER_RAINY",
		"WEATHER_FOGGY",
		"WEATHER_EXTRA_SUNNY",
		"WEATHER_HURRICANE",
		"WEATHER_EXTRACOLOURS",
		"WEATHER_ULTRASUNNY",
	};

	uint16_t* p = EMUPOINTER<uint16_t*>(0x095DA378);
	for (int i = 0; i < 256; i += 4) {
		printf("%s, %s, %s, %s,\n", w[p[i]], w[p[i + 1]], w[p[i + 2]], w[p[i + 3]]);
	}

#endif

	// radar tex
#if 0
	uint32_t* radarCompressedTextures = EMUPOINTER<uint32_t*>(0x0989738C);
	for (int i = 0; i < 64; i++) {
		sprintf(buff, "radarCompressedTextures_%d_texture", i);
		GEN_FIX_OFFSET(file, radarCompressedTextures[i], nil, buff, false, 0, true);
	}
#endif

	// Combat
#if 1
#if 1
	{
		CCombatMoves* pMoves = (CCombatMoves*)gpFightMoves;
		if (pMoves)
		{
			// psp-указатель на сам экземпляр CCombatMoves (значение по адресу 0x08BAA5B0)
			uint32_t pspMoves = *EMUPOINTER<uint32_t*>(0x08BAA5B0);
			if (pspMoves)
			{
				// === SECTION A : CCombatMoves (self) ===
				GEN_FIX_OFFSET(file, pspMoves, "CCombatMoves", "", true); // set type
				//GEN_FIX_OFFSET(file, pspMoves, "CCombatMoves", "CCombatMoves_main");

				// === SECTION B : CCombatMoveData_A_A[] (m_DataA.m_aArr) ===
				if (pMoves->m_DataA.m_nCount > 0 && pMoves->m_DataA.m_aArr)
				{
#if 0 // ставим каждый елемент как CCombatMoveData_A_A*, ставим объект указания CCombatMoveData_A_A и групируем масив указателей но не работает теряет в void*
					// ВАЖНО: каст к uint32_t ДО арифметики, иначе компилятор
					// домножит i*sizeof(void*) ещё раз на sizeof(CCombatMoveData_A_A*)
					uint32_t pBaseArr = (uint32_t)pMoves->m_DataA.m_aArr;
					for (int32_t i = 0; i < pMoves->m_DataA.m_nCount; i++)
					{
						// адрес i-й ячейки массива (по 4 байта)
						uint32_t pSlot = pBaseArr + (uint32_t)(i * sizeof(void*));

						// (1) тип самой ячейки: CCombatMoveData_A_A* (только тип, имя не ставим —
						//     его поставит MakeArray позже)
						GEN_FIX_OFFSET(file, pSlot, "CCombatMoveData_A_A*", "", /*typeOnly*/true); // елемент масива указателей

						// (2) тип того, на что указывает ячейка: CCombatMoveData_A_A
						uint32_t pElem = *EMUPOINTER<uint32_t*>(pSlot);
						if (!pElem) continue;

						sprintf(buff, "CCombatMoveData_A_A_%d", i);
						GEN_FIX_OFFSET(file, pElem, "CCombatMoveData_A_A", buff);
					}

					// (3) MakeArray по базе
					sprintf(buff, "CCombatMoveData_A_A_aArr");
					GEN_FIX_OFFSET(file, pBaseArr, "CCombatMoveData_A_A*", buff,
						/*typeOnly*/false, pMoves->m_DataA.m_nCount, /*nameOnly*/false);

					// (4) MakeArray сбрасывает имя -> восстанавливаем
					GEN_FIX_OFFSET(file, pBaseArr, "", buff, false, 0, /*nameOnly*/true);
#endif
					sprintf(buff, "CCombatMoveData_A_A_aArr");
					GEN_FIX_OFFSET(file, (uint32_t)pMoves->m_DataA.m_aArr, "", buff,
						/*typeOnly*/false, pMoves->m_DataA.m_nCount, /*nameOnly*/false);

					char arrayDecl[128];
					sprintf(arrayDecl, "CCombatMoveData_A_A *CCombatMoveData_A_A_aArr[%d]", pMoves->m_DataA.m_nCount);
					GEN_ARRAY(file, (uint32_t)pMoves->m_DataA.m_aArr, arrayDecl);
				}

				// === SECTION C / E / F / G : CCombatMove[] (m_MovesData.m_aMoves) ===
				if (pMoves->m_MovesData.m_nMoveCount > 0 && pMoves->m_MovesData.m_aMoves)
				{
					CCombatMove* moves = EMUPOINTER<CCombatMove*>(pMoves->m_MovesData.m_aMoves);
					if (moves)
					{
						for (int32_t i = 0; i < pMoves->m_MovesData.m_nMoveCount; i++)
						{
							CCombatMove* mv = &moves[i];
							uint32_t pMovePsp = (uint32_t)pMoves->m_MovesData.m_aMoves
								+ (uint32_t)(i * sizeof(CCombatMove));

							sprintf(buff, "CCombatMove_%d", i);
							GEN_FIX_OFFSET(file, pMovePsp, "CCombatMove", buff);

							// --- SECTION E : CCombatMove_A[] ---
							if (mv->m_nCount_A > 0 && mv->m_aArr_A)
							{
								CCombatMove_A* arrA = EMUPOINTER<CCombatMove_A*>(mv->m_aArr_A);
								for (int32_t j = 0; j < mv->m_nCount_A; j++)
								{
									CCombatMove_A* pA = &arrA[j];
									uint32_t pAPsp = (uint32_t)mv->m_aArr_A
										+ (uint32_t)(j * sizeof(CCombatMove_A));
									sprintf(buff, "CCombatMove_A_%d_%d", i, j);
									GEN_FIX_OFFSET(file, pAPsp, "CCombatMove_A", buff);

									// ---- m_aArr_A : offset 0x00 -> CCombatMove_A_A* ----
									if (pA->m_aArr_A)
									{
										uint32_t pArr = (uint32_t)pA->m_aArr_A;
										// элементы массива — цепочка CCombatMove_A_<i>_<j>_A_<k>
										for (int32_t k = 0; k < 1; k++) // todo count неизвестен, пока 1
										{
											uint32_t pElem = pArr + (uint32_t)(k * sizeof(CCombatMove_A_A));
											sprintf(buff, "CCombatMove_A_%d_%d_A_%d", i, j, k);
											GEN_FIX_OFFSET(file, pElem, "CCombatMove_A_A", buff);
										}
									}

									// ---- m_aArr_B : offset 0x10 -> CCombatMove_A_A* ----
									if (pA->m_aArr_B)
									{
										uint32_t pArr = (uint32_t)pA->m_aArr_B;
										for (int32_t k = 0; k < 1; k++) // todo count неизвестен, пока 1
										{
											uint32_t pElem = pArr + (uint32_t)(k * sizeof(CCombatMove_A_B));
											sprintf(buff, "CCombatMove_A_%d_%d_B_%d", i, j, k);
											GEN_FIX_OFFSET(file, pElem, "CCombatMove_A_B", buff);
										}
									}

								}
								sprintf(buff, "CCombatMove_A_%d_arr", i);
								GEN_FIX_OFFSET(file, (uint32_t)mv->m_aArr_A, "CCombatMove_A*", buff,
									false, mv->m_nCount_A, false);
								GEN_FIX_OFFSET(file, (uint32_t)mv->m_aArr_A, "", buff, false, 0, true);
							}

							// --- SECTION F / G : CCombatMove_B[] ---
							if (mv->m_nCount_B > 0 && mv->m_aArr_B)
							{
								CCombatMove_B* arrB = EMUPOINTER<CCombatMove_B*>(mv->m_aArr_B);
								for (int32_t j = 0; j < mv->m_nCount_B; j++)
								{
									CCombatMove_B* mvB = &arrB[j];
									uint32_t pBPsp = (uint32_t)mv->m_aArr_B
										+ (uint32_t)(j * sizeof(CCombatMove_B));

									sprintf(buff, "CCombatMove_B_%d_%d", i, j);
									GEN_FIX_OFFSET(file, pBPsp, "CCombatMove_B", buff);

									// --- SECTION G : CCombatMove_B_A[] ---
									if (mvB->m_nCount > 0 && mvB->m_aArr)
									{
										for (int32_t k = 0; k < mvB->m_nCount; k++)
										{
											uint32_t pBAPsp = (uint32_t)mvB->m_aArr
												+ (uint32_t)(k * sizeof(CCombatMove_B_A));
											sprintf(buff, "CCombatMove_B_A_%d_%d_%d", i, j, k);
											GEN_FIX_OFFSET(file, pBAPsp, "CCombatMove_B_A", buff);
										}
										sprintf(buff, "CCombatMove_B_A_%d_%d_arr", i, j);
										GEN_FIX_OFFSET(file, (uint32_t)mvB->m_aArr, "CCombatMove_B_A*", buff,
											false, mvB->m_nCount, false);
										GEN_FIX_OFFSET(file, (uint32_t)mvB->m_aArr, "", buff, false, 0, true);
									}
								}
								sprintf(buff, "CCombatMove_B_%d_arr", i);
								GEN_FIX_OFFSET(file, (uint32_t)mv->m_aArr_B, "CCombatMove_B*", buff,
									false, mv->m_nCount_B, false);
								GEN_FIX_OFFSET(file, (uint32_t)mv->m_aArr_B, "", buff, false, 0, true);
							}
						}
						sprintf(buff, "CCombatMove_arr");
						GEN_FIX_OFFSET(file, (uint32_t)pMoves->m_MovesData.m_aMoves, "CCombatMove*",
							buff, false, pMoves->m_MovesData.m_nMoveCount, false);
						GEN_FIX_OFFSET(file, (uint32_t)pMoves->m_MovesData.m_aMoves, "", buff, false, 0, true);
					}
				}

				// === SECTION D : CCombatMoveData_B_A[] (m_DataB.m_aArr) ===
				if (pMoves->m_DataB.m_nCount > 0 && pMoves->m_DataB.m_aArr)
				{
					for (int32_t i = 0; i < pMoves->m_DataB.m_nCount; i++)
					{
						uint32_t pPsp = (uint32_t)pMoves->m_DataB.m_aArr
							+ (uint32_t)(i * sizeof(CCombatMoveData_B_A));
						sprintf(buff, "CCombatMoveData_B_A_%d", i);
						GEN_FIX_OFFSET(file, pPsp, "CCombatMoveData_B_A", buff);
					}
					sprintf(buff, "CCombatMoveData_B_aArr");
					GEN_FIX_OFFSET(file, (uint32_t)pMoves->m_DataB.m_aArr, "CCombatMoveData_B_A*",
						buff, false, pMoves->m_DataB.m_nCount, false);
					GEN_FIX_OFFSET(file, (uint32_t)pMoves->m_DataB.m_aArr, "", buff, false, 0, true);
				}
			}
		}
	}
#endif

#if 0
		CCombatStats* pStats = (CCombatStats*)gpFightStats;
		if (pStats)
		{
			// psp-указатель на сам экземпляр CCombatStats (значение по адресу 0x08BAB230)
			uint32_t pspStats = *EMUPOINTER<uint32_t*>(0x08BAB230);
			if (pspStats)
			{
				// === SECTION A : CCombatStats (self) ===
				GEN_FIX_OFFSET(file, pspStats, "CCombatStats", "", true); // set type
				//GEN_FIX_OFFSET(file, pspStats, "CCombatStats", "CCombatStats_array");

				if (pStats->m_nNumStats > 0 && pStats->m_aStats)
				{
					CCombatStat* stats = EMUPOINTER<CCombatStat*>(pStats->m_aStats);
					if (stats)
					{
						// === SECTION B / C / D / E : CCombatStat[] ===
						for (int32_t i = 0; i < pStats->m_nNumStats; i++)
						{
							CCombatStat* pStat = &stats[i];
							uint32_t pStatPsp = ((uint32_t)pStats->m_aStats) + (uint32_t)(i * sizeof(CCombatStat));

							sprintf(buff, "CCombatStat_%d", i);
							GEN_FIX_OFFSET(file, pStatPsp, "CCombatStat", buff);

							// --- SECTION C : CCombatStat_A[] ---
							if (pStat->m_nCount_A > 0 && pStat->m_aArr_A)
							{
								for (int32_t j = 0; j < pStat->m_nCount_A; j++)
								{
									uint32_t pAPsp = ((uint32_t)pStat->m_aArr_A) + (uint32_t)(j * sizeof(CCombatStat_A));
									sprintf(buff, "CCombatStat_A_%d_%d", i, j);
									GEN_FIX_OFFSET(file, pAPsp, "CCombatStat_A", buff);
								}
								sprintf(buff, "CCombatStat_A_%d_arr", i);
								GEN_FIX_OFFSET(file, (uint32_t)pStat->m_aArr_A, "CCombatStat_A*", buff, false, pStat->m_nCount_A, false); //arr
								GEN_FIX_OFFSET(file, (uint32_t)pStat->m_aArr_A, "", buff, false, 0, true); // name
							}

							// --- SECTION D / E : CCombatStat_B[] ---
							if (pStat->m_nCount_B > 0 && pStat->m_aArr_B)
							{
								CCombatStat_B* arrB = EMUPOINTER<CCombatStat_B*>(pStat->m_aArr_B);
								for (int32_t j = 0; j < pStat->m_nCount_B; j++)
								{
									CCombatStat_B* pB = &arrB[j];
									uint32_t pBPsp = ((uint32_t)pStat->m_aArr_B) + (uint32_t)(j * sizeof(CCombatStat_B));

									sprintf(buff, "CCombatStat_B_%d_%d", i, j);
									GEN_FIX_OFFSET(file, pBPsp, "CCombatStat_B", buff);

									// --- SECTION E : CCombatStat_B_A (pB->m_pData) ---
									if (pB->m_pData)
									{
										sprintf(buff, "CCombatStat_B_A_%d_%d", i, j);
										GEN_FIX_OFFSET(file, (uint32_t)pB->m_pData, "CCombatStat_B_A", buff);
									}
								}
								sprintf(buff, "CCombatStat_B_%d_arr", i);
								GEN_FIX_OFFSET(file, (uint32_t)pStat->m_aArr_B, "CCombatStat_B*", buff, false, pStat->m_nCount_B, false); // arr
								GEN_FIX_OFFSET(file, (uint32_t)pStat->m_aArr_B, "", buff, false, 0, true); // name
							}
						}

						GEN_FIX_OFFSET(file, (uint32_t)pStats->m_aStats, "CCombatStat*", "CCombatStat_arr", false, pStats->m_nNumStats, false); // arr
						GEN_FIX_OFFSET(file, (uint32_t)pStats->m_aStats, "", "CCombatStat_arr", false, 0, true); // name
					}
				}
			}
		}
#endif
#endif

	if (file) {
		fprintf(file, "Message(\"IDC Done\\n\");\n");
		fclose(file);
	}
	printf("FixupEtc DUMPED!\n");
}

void TestModelInfo()
{
	//CSimpleModelInfo* miwithatomics = nil;
	//for (int32_t i = 0; i < CModelInfo_msNumModelInfos; i++) {
	//	CBaseModelInfo* modelInfo = GetModelInfo(i);
	//	if (modelInfo && modelInfo->m_type == MITYPE_SIMPLE && ((CSimpleModelInfo*)modelInfo)->m_atomics_objects)
	//	{
	//		miwithatomics = ((CSimpleModelInfo*)modelInfo);
	//		break;
	//	}
	//}
	//if (!miwithatomics)
	//	return;

	for (int32_t i = 0; i < CModelInfo_msNumModelInfos; i++) {
		CBaseModelInfo* modelInfo = GetModelInfo(i);
		ModelInfoExt* pInfoEx = GetModelInfoExt(i);
		if (!modelInfo) continue;



		//continue; //------------------------------------------------------



		//if (modelInfo->m_type == MITYPE_SIMPLE)
		//{
		//	//CSimpleModelInfo* mi = (CSimpleModelInfo*)modelInfo;
		//	//RpAtomic** at = EMUPOINTER<RpAtomic**>(mi->m_atomics_objects);
		//	////if(mi->m_numAtomics)
		//	////	printf("mi %d: simple m_numAtomics %d at  0x%p, 1st 0xp\n", i, mi->m_numAtomics, mi->m_atomics_objects/*, EMUPOINTER<RpAtomic*>(at[0])*/);
		//	////GetModelInfoExt(i)->allcolls.push_back(modelInfo->m_colModel);
		//	////if (!at)
		//	//{
		//	//	mi->m_atomics_objects = miwithatomics->m_atomics_objects; // ps2 ptr
		//	//	mi->m_numAtomics = miwithatomics->m_numAtomics;

		//	//	//mi->m_atomics_objects = (RwObject**)0x1234567;
		//	//	//mi->m_numAtomics = 7777;
		//	//	printf("%d patched\n", i);
		//	//}
		//}

		switch (modelInfo->m_type)
		{
			case MITYPE_VEHICLE:
			{
				tVehicleSampleData* m_SampleData = OFFSET(modelInfo, 0x284, tVehicleSampleData*);
				//printf("[%d] - m_nAccelerationSampleIndex:%d m_nHornSample:%d m_nSirenOrAlarmSample:%d\n", i, m_SampleData->m_nAccelerationSampleIndex, m_SampleData->m_nHornSample, m_SampleData->m_nSirenOrAlarmSample);
				printf("%s %d %d %d %d %d %d %d\n", pInfoEx->name.c_str(), m_SampleData->m_nAccelerationSampleIndex, m_SampleData->m_nBank, 
					m_SampleData->m_nHornSample, m_SampleData->m_nHornFrequency, m_SampleData->m_nSirenOrAlarmSample,
					m_SampleData->m_nSirenOrAlarmFrequency, m_SampleData->m_bDoorType);
				break;


				void* m_pHandlingData = EMUPOINTER<void*>(*OFFSET(modelInfo, 0x38, uint32_t*));
				void* m_pHandlingBike = EMUPOINTER<void*>(*OFFSET(modelInfo, 0x3C, uint32_t*));
				void* m_pHandlingFlying = EMUPOINTER<void*>(*OFFSET(modelInfo, 0x40, uint32_t*));
				void* m_pHandlingBoat = EMUPOINTER<void*>(*OFFSET(modelInfo, 0x44, uint32_t*));
				void* m_pHandlingJetski = EMUPOINTER<void*>(*OFFSET(modelInfo, 0x48, uint32_t*));
				void* m_pHandling6atv = EMUPOINTER<void*>(*OFFSET(modelInfo, 0x4C, uint32_t*));
				//printf("%d -> HandlingData 0x%p HandlingBike 0x%p HandlingFlying 0x%p HandlingBoat 0x%p HandlingJetski 0x%p pHandling6atv 0x%p\n",
				//	i, m_pHandlingData, m_pHandlingBike, m_pHandlingFlying, m_pHandlingBoat, m_pHandlingJetski, m_pHandling6atv);

				uint8_t& _96 = *OFFSET(m_pHandlingData, 0x96, uint8_t*);
				uint8_t& _97 = *OFFSET(m_pHandlingData, 0x97, uint8_t*);
				uint32_t& _9C = *OFFSET(m_pHandlingData, 0x97, uint32_t*);
				float& _f9C = *OFFSET(m_pHandlingData, 0x97, float*);
				printf("%d -> _96 %d  _97 %d  _9C %d  _f9C %f\n", i, _96, _97, _9C, _f9C);

				float& fDragMult = *OFFSET(m_pHandlingData, 0x98, float*);
				float& fMass = *OFFSET(m_pHandlingData, 0xBC, float*);
				float& _64 = *OFFSET(m_pHandlingData, 0x64, float*);
				printf("%d -> fDragMult %f  fMass %f %f \n\n", i, fDragMult, fMass, _64);
				fMass = 255000.0f;
				//CVehicleModelInfo* vmi = (CVehicleModelInfo*)modelInfo;
				//char* tBounceData = EMUPOINTER<char*>(*(uint32_t*)(((char*)vmi) + (0x44)));
				//float* fBoatVolumeDistribution = (float*)(tBounceData ? (tBounceData + 0x40) : null);
				//float* scaleMax = (float*)(tBounceData ? (tBounceData + 0x70) : null);
				//float* scaleMin = (float*)(tBounceData ? (tBounceData + 0x80) : null);
				//printf("mi %d, 0x%p\n", i, vmi);
				//printf("mi %d, 0x%p 0x%p\n", i, vmi, fBoatVolumeDistribution);
				//if (fBoatVolumeDistribution) { printf("mi %d, %f %f %f %f %f %f %f %f %f\n", i,
				//	fBoatVolumeDistribution[0], fBoatVolumeDistribution[1], fBoatVolumeDistribution[2],
				//	fBoatVolumeDistribution[3], fBoatVolumeDistribution[4], fBoatVolumeDistribution[5],
				//	fBoatVolumeDistribution[6], fBoatVolumeDistribution[7], fBoatVolumeDistribution[8]
				//);
				//if (fBoatVolumeDistribution) {
				//	//printf("mi %d %s\n", i, (fBoatVolumeDistribution[8] == 0.6f ? "fBoatVolumeDistributionSpeed" : "fBoatVolumeDistribution"));
				//	printf("mi %d  MAX %f %f %f    MIN %f %f %f\n", i, scaleMax[0], scaleMax[1], scaleMax[2],
				//		scaleMin[0], scaleMin[1], scaleMin[2]);
				//}

				//printf("mi %d, 0x%p %s, t %d ws %f\n", i, vmi, vmi->m_gameName, vmi->m_vehicleType,  vmi->m_wheelScale);
				break;
			}
		}
	}
}

void* GetPointer() {
	void* p = NULL;
	if (scanf("%p", &p) != 1) return NULL;
		//if (scanf("0x%p", &p) != 1) return NULL;
	return p;
}

void DumpSfx()
{
	//FILE* file = fopen("C:\\SFXPSP.txt", "w");
	tSample* gSampleDataTable = EMUPOINTER<tSample*>(*EMUPOINTER<int*>(0x08BADD98));
	for (int i = 0; i < 7780; i++) {
		//fprintf(file, "[%d] nOffset:%d  nSize:%d  nFrequency:%d\n", i, gSampleDataTable[i].nOffset, gSampleDataTable[i].nSize, gSampleDataTable[i].nFrequency);
		printf("[%d] nOffset:%d  nSize:%d  nFrequency:%d\n", i, gSampleDataTable[i].nOffset, gSampleDataTable[i].nSize, gSampleDataTable[i].nFrequency);
	}
	//fclose(file);
	printf("SFX DUMPED!\n");
}

void NOP(void* p, int size) {
	for (int i = 0; i < size; i++) {
		((uint8_t*)p)[i] = 0x0;
	}
}

void PatchNoMPCars()
{
	//printf("PatchNoMPCars\n");
	{
		*EMUPOINTER<int*>(0x08AC50B8) = 0x0; // no CCarCtrl::GenerateRandomCars();
		//*EMUPOINTER<int*>(0x08AC50C0) = 0x0; // no CRoadBlocks::GenerateRoadBlocks();
		//*EMUPOINTER<int*>(0x08AC4F70) = 0x0; // no CPopulation::Update(true);
		//*EMUPOINTER<int*>(0x08933EC8) = 0x0; // no sync
		//NOP(EMUPOINTER<int*>(0x08B4969C), 0x08B496D8 - 0x08B4969C);
	}
}

void LogZone(int id, int ackdt)
{
	static std::vector<std::pair<int, int>> idMaxAckdt;
	auto it = std::find_if(idMaxAckdt.begin(), idMaxAckdt.end(),
		[id](const std::pair<int, int>& element) { return element.first == id; });

	if (it != idMaxAckdt.end())
	{
		if (ackdt > it->second)
			it->second = ackdt;
	}
	else {
		idMaxAckdt.push_back(std::make_pair(id, ackdt));
	}

	std::cout << "ID: " << id << ", ackdt: ";
	auto currentIt = std::find_if(idMaxAckdt.begin(), idMaxAckdt.end(),
		[id](const std::pair<int, int>& element) { return element.first == id; });

	if (currentIt != idMaxAckdt.end())
	{
		std::cout << currentIt->second << std::endl;
	}
	else
	{
		std::cout << "не найден" << std::endl;
	}
}

void TestPool()
{
	for (int32_t i = CPools_ms_pObjectPool->m_nSize - 1; i >= 0; i--)
	{
		if (CPools_GetSlotIsFree(CPools_ms_pObjectPool, i)) { continue; }
		CEntity* e = (CEntity*)CPools_GetSlot(CPools_ms_pObjectPool, i, 544);
		if (e)
		{
			uint8_t CE_0_07_flags_A   = *OFFSET(e, 0x48, uint8_t*);
			uint8_t CE_1_815_flags_B  = *OFFSET(e, 0x49, uint8_t*);
			uint8_t CE_2_1623_flags_C = *OFFSET(e, 0x4A, uint8_t*);
			uint8_t CE_3_2431_flags_D = *OFFSET(e, 0x4B, uint8_t*);
			uint8_t CE_4_3239_flags_E = *OFFSET(e, 0x4C, uint8_t*);
			uint8_t CE_5_4047_flags_F = *OFFSET(e, 0x4D, uint8_t*);
			uint8_t CE_6_4855_flags_G = *OFFSET(e, 0x4E, uint8_t*);
			uint8_t CE_7_5663_flags_H = *OFFSET(e, 0x4F, uint8_t*);
			bool bStreamBIGBuilding = GET_BIT(CE_3_2431_flags_D, 0);
			bool bIsSubway = GET_BIT(CE_4_3239_flags_E, 3);
			bool bIsStatic = GET_BIT(CE_1_815_flags_B, 3);
			//if (bStreamBIGBuilding) // LOD
			//	printf("bStreamBIGBuilding 1 %d %s\n", e->m_modelIndex, GetModelInfoExt(e->m_modelIndex)->name.c_str());
			//if (bIsSubway)
			//	printf("bIsSubway 1 %d %s\n", e->m_modelIndex, GetModelInfoExt(e->m_modelIndex)->name.c_str()); // noone

			int micrate = 7306;
			//if(e->m_modelIndex == micrate && bIsStatic)
			//	printf("bIsStatic 1 %d %s\n", e->m_modelIndex, GetModelInfoExt(e->m_modelIndex)->name.c_str());

			if (e->m_modelIndex == micrate) {
				int m_pAttachedTo = *OFFSET(e, 0x1C0, int*);

				printf("bIsStatic %d %d %s att:0x%p\n", bIsStatic, e->m_modelIndex, GetModelInfoExt(e->m_modelIndex)->name.c_str(), m_pAttachedTo);

			}
		}
	}

	//for (int32_t i = CPools_ms_pBuildingPool->m_nSize - 1; i >= 0; i--)
	//{
	//	if (CPools_GetSlotIsFree(CPools_ms_pBuildingPool, i)) { continue; }
	//	CEntity* e = (CEntity*)CPools_GetSlot(CPools_ms_pBuildingPool, i, 96);
	//	if (e)
	//	{

	//		uint8_t CE_3_2431_flags_D = *OFFSET(e, 0x4B, uint8_t*);
	//		uint8_t CE_4_3239_flags_E = *OFFSET(e, 0x4C, uint8_t*);
	//		bool bStreamBIGBuilding = GET_BIT(CE_3_2431_flags_D, 0);
	//		bool bIsSubway = GET_BIT(CE_4_3239_flags_E, 3);
	//		//if (bStreamBIGBuilding) // LOD
	//		//	printf("bStreamBIGBuilding 1 %d %s\n", e->m_modelIndex, GetModelInfoExt(e->m_modelIndex)->name.c_str());
	//		if (bIsSubway)
	//			printf("bIsSubway 1 %d %s\n", e->m_modelIndex, GetModelInfoExt(e->m_modelIndex)->name.c_str()); // noone
	//	}
	//}
	//printf("TestPool end\n");
}

void DumpEscalators()
{
	FILE* file = fopen("C:\\IDC\\dtzhater.txt", "w");
	int NumEscalators = *EMUPOINTER<int*>(0x08BB3F18);
	CEscalator* aArray = EMUPOINTER<CEscalator*>(*EMUPOINTER<int*>(0x08BB3F1C));
	for (int i = 0; i < NumEscalators; i++) {
		fprintf(file, "pos0 %f %f %f  pos1 %f %f %f  pos2 %f %f %f  pos3 %f %f %f  m_bIsMovingDown %s %d\n",
			aArray[i].m_pos0.x, aArray[i].m_pos0.y, aArray[i].m_pos0.z,
			aArray[i].m_pos1.x, aArray[i].m_pos1.y, aArray[i].m_pos1.z,
			aArray[i].m_pos2.x, aArray[i].m_pos2.y, aArray[i].m_pos2.z,
			aArray[i].m_pos3.x, aArray[i].m_pos3.y, aArray[i].m_pos3.z,
			aArray[i].m_bIsMovingDown ? "true" : "false", aArray[i].m_stepsCount);
	}
	fclose(file);
	printf("DumpEscalators DUMPED!\n");
}

void DumpCombat()
{
	FILE* file = fopen("C:\\IDC\\combat.txt", "w");
	int num = 0x68;
	uint8_t* pCombatMoves = EMUPOINTER<uint8_t*>(0x095DEC00);

	for (int i = 0; i < num; i++) {
		uint8_t* pCurr = pCombatMoves + (0x40 * i);
		char* pName = (char*)(pCurr + 0x33);
		if(pName[0])
			fprintf(file, "%d %s\n", i, pName);
		else
			fprintf(file, "%d ---\n", i, pName);
	}
	fclose(file);
	printf("DumpCombat DUMPED!\n");
}

void DumpSfx2()
{
	int* aEngineSounds = EMUPOINTER<int*>(0x08B7AC98);
	int* aEngineSoundsMG = EMUPOINTER<int*>(0x08B820F0);
	int* gOneShotCol = EMUPOINTER<int*>(0x08B81218);
	//printf("aEngineSounds\n");
	//for (int x = 0; x < 24 * 2; x += 2) {
	//	printf("%d, %d\n", aEngineSounds[x], aEngineSounds[x + 1]);
	//}
	printf("aEngineSoundsMG\n");
	for (int x = 0; x < 24 * 2; x += 2) {
		printf("%d, %d\n", aEngineSoundsMG[x], aEngineSoundsMG[x + 1]);
	}
	//printf("\ngOneShotCol\n");
	//for (int x = 0; x < 35; x++) {
	//	printf("%d\n", gOneShotCol[x]);
	//}
}

void Test()
{
	CEntity* p = FindPlayerPed();
	CEntity* v = EMUPOINTER<CEntity*>(*OFFSET(p, 0x480, int*));
	if (v) {
		CRGBA* c = OFFSET(v, 0x224, CRGBA*);
		CRGBA r = { 255, 0, 0, 0};
		c[0] = r; // no alpha
		c[1] = r;
		//strcpy(c, "\xFF\xFF\xFF\0\xFF\xFF\xFF\0");
	}
}


void OnBtn()
{
	//TestPool();
	//MakeIDCMLO();
	//FixupMLOPATCHES();
	//FixupMarkers();
	//FixupPools();
	//DumpEscalators();
	//GenRelocComs();
	//FixupInter();
	//FixupStatsTypes();
	FixupEtc();
	//DumpCombat();
	//DumpSfx2();
	Test();
	printf("OnBtn end\n");
	return;
	TestModelInfo();
	DumpSfx();


}

const char* GetElementType(uint8_t* pElement)
{
	uint32_t vft = *OFFSET(pElement, 0x6C, uint32_t*);
	switch (vft)
	{
		case 0x08BA7BA0:
			return "sBike";
		case 0x08BA7080:
			return "sPickup";
		case 0x08BA63F8:
			return "sPed";
		case 0x08BA4AD0:
			return "sPlayer";
		case 0x08BA6BB0:
			return "sAutomobile";
		default:
			printf("GetElementType 0x%X\n", vft);
			return "UNKNOWN TODO";
	}
	return nil;
}

bool bPatchMp = false;
void UpdMP()
{
	*EMUPOINTER<int*>(0x8BB2534) = rand() % 6; // SetNewLineAdd/SetDropShadowPosition ?


	if(bPatchMp)
		PatchNoMPCars(); // prevent restore patch from load state

	//uint32_t* C3dMarkers_m_pRslElementGroupArray = *EMUPOINTER<uint32_t**>(0x08BB3E5C);
	//printf("\n");
	//printf("%p \n", C3dMarkers_m_pRslElementGroupArray);
	//for (int32_t i = 0; i < 10; i++) // 9
	//{
	//	uint32_t* pAtomic = EMUPOINTER<uint32_t*>(C3dMarkers_m_pRslElementGroupArray[i]);
	//	printf(" %d -> 0x%p\n", i, pAtomic ? pAtomic : 0);
	//}


	bool& gIsMultiplayerGame = *EMUPOINTER<bool*>(0x08BB01B8);
	bool& gDeveloperFlag = *EMUPOINTER<bool*>(0x08BB2DBC);
	float& CTimer_ms_fTimeStepNonClipped = *EMUPOINTER<float*>(0x08BB3B64);

	gDeveloperFlag = true; // allow mp start at only host
	// dis timeout
	*EMUPOINTER<char*>(0x08AC45B0) = 1; // MULTI_ABORT_PLAYER_COUNT
	//if(cNetSession_mspInst) *OFFSET(cNetSession_mspInst, 0x68, uint32_t*) = 1; // m_nPeerCount unlock update send + simsch
	*EMUPOINTER<int*>(0x08ADB41C) = 0x0; // unlock update send + simsch // same + orgi count
	*EMUPOINTER<int*>(0x08AC4768) = 0x0; // abort 15 sec
	*EMUPOINTER<int*>(0x08ADB6AC) = 0x0; // no update timout function

	//*EMUPOINTER<int*>(0x0898B858 + 0x0) = 0x0; // allow mp cheats
	//*EMUPOINTER<int*>(0x0898B858 + 0x4) = 0x0;
	//*EMUPOINTER<int*>(0x0898B858 + 0x8) = 0x0;
	//*EMUPOINTER<int*>(0x0898B858 + 0xC) = 0x0;
	//*EMUPOINTER<int*>(0x0898B858 + 0x10) = 0x0;
	// MULTI_TIME_OUT_4  08AC475C

	if(*EMUPOINTER<int*>(0x08BB1AC8))
	{
		return;

		const char* a[] = {
			"STREAMSTATE_NOTLOADED",
			"STREAMSTATE_LOADED",
			"STREAMSTATE_INQUEUE",
			"STREAMSTATE_READING", // channel is reading
			"STREAMSTATE_STARTED", // first part loaded
		};
		void* CStreaming_mspInst = EMUPOINTER<void*>(*EMUPOINTER<int*>(0x08BB1AC8));
		if (!*OFFSET(CStreaming_mspInst, 0x98, int*)) return;
		CStreamingInfo* ms_aInfoForModel = EMUPOINTER<CStreamingInfo*>(*OFFSET(CStreaming_mspInst, 0x98, int*));
		for (int i = 0+199; i < 200; ++i)
		printf("\r%3d stream %d 0x%p (%-20s)", i, ms_aInfoForModel[i].m_loadState,
			OFFSET(*OFFSET(CStreaming_mspInst, 0x98, int*), (sizeof(CStreamingInfo)*i)+4+4, void*),
			a[ms_aInfoForModel[i].m_loadState]);

		return;
	}

	if (BTN('H'))
	{
		printf("cAdhoc_mspInst: PC:0x%p PSP:0x%p\n", cAdhoc_mspInst, *(uintptr_t**)IDATRANSLATE(0x08BB344C));
		printf("cLobby_mspInst: PC:0x%p PSP:0x%p\n", cLobby_mspInst, *(uintptr_t**)IDATRANSLATE(0x08BB3458));
		printf("cPeerManager_mspInst: PC:0x%p PSP:0x%p\n", cPeerManager_mspInst, *(uintptr_t**)IDATRANSLATE(0x08BB3450));
		printf("TheMPGame: PC:0x%p PSP:0x%p\n", TheMPGame, 0x08BC8FC0);
		printf("cNetSession_mspInst: PC:0x%p PSP:0x%p\n\n", cNetSession_mspInst, *(uintptr_t**)IDATRANSLATE(0x8BC9024));
		Sleep(500);

		{
			OnBtn();
		}
	}


	// Zones
	{
		//uint8_t* Rb_Tree_m_ZoneManager_m_mZones = OFFSET(TheMPGame, 0x74, uint8_t*); // Rb_Tree
		//uint8_t* pHeader = EMUPOINTER<uint8_t*>(*(int*)Rb_Tree_m_ZoneManager_m_mZones); // TheMPGame.m_ZoneManager.m_mZones(Rb_Tree).header(Rb_Node)
		////int size = *(int*)(Rb_Tree_m_ZoneManager_m_mZones + 4);
		//int size = *OFFSET(Rb_Tree_m_ZoneManager_m_mZones, 0x4, int*);
		//printf("pHeader: 0x%p, %d\n", pHeader, size); // sz4
		//printf("PPSSPP_BASE: 0x%p\n", PPSSPP_BASE);

		uint8_t* Rb_Tree_m_ZoneManager_m_mZones = OFFSET(TheMPGame, 0x74, uint8_t*); // host ptr на Rb_Tree
		int header_raw = *(int*)OFFSET(Rb_Tree_m_ZoneManager_m_mZones, 0x0, int*);     // raw ppsspp pointer (header)
		int size = *(int*)OFFSET(Rb_Tree_m_ZoneManager_m_mZones, 0x4, int*);
		//printf("pHeader_raw: 0x%08X, size: %d\n", header_raw, size);
		//printf("PPSSPP_BASE: 0x%p\n", PPSSPP_BASE);

		int node_raw = 0;
		if (header_raw) {
			uint8_t* host_header = EMUPOINTER<uint8_t*>(header_raw);
			node_raw = *OFFSET(host_header, 0x08, int*); // header->left (raw)
		}

		int iter = 0;
		while (node_raw && node_raw != header_raw) {
			// host pointer к текущему узлу
			uint8_t* host_node = EMUPOINTER<uint8_t*>(node_raw);

			// элемент (wrapper ptr) — raw
			int elem_raw = *OFFSET(host_node, 0x14, int*);
			uint8_t* host_elem = elem_raw ? EMUPOINTER<uint8_t*>(elem_raw) : nullptr;
			//printf("elem_raw: 0x%08X, host_elem: %p\n", elem_raw, host_elem);

			if (host_elem) {
				uint8_t* pZone = host_elem;
				int16_t zone_id = *OFFSET(pZone, 0x0, int16_t*);

				// log ack
				//{
				//	uint8_t* m_vAck = OFFSET(pZone, 0x30, uint8_t*);
				//	int pStart = (*(int*)(m_vAck + 0));
				//	int pEnd = (*(int*)(m_vAck + 4));
				//	LogZone(zone_id, (pEnd - pStart));
				//	printf("ID: %d ackDT %d\n", zone_id, (pEnd - pStart));
				//}

				// elements
				{
					uint32_t m_nCurTime = *OFFSET(pZone, 0x4, uint32_t*);
					uint16_t m_nBasis = *OFFSET(pZone, 0xA, uint16_t*);
					uint32_t* m_vElementsS = EMUPOINTER<uint32_t*>(*OFFSET(pZone, 0x18, uint32_t*));
					uint32_t* m_vElementsE = EMUPOINTER<uint32_t*>(*OFFSET(pZone, 0x18 + 0x4, uint32_t*));
					int elems = m_vElementsE - m_vElementsS;
					printf("zone 0x%p ID: %d m_nCurTime %d  m_nBasis %d elems %d\n", elem_raw, zone_id, m_nCurTime, m_nBasis, elems);
					for (int i = 0; i < elems; i++) {
						int pelem = m_vElementsS[i];
						uint8_t* realelem = pelem ? EMUPOINTER<uint8_t*>(pelem) : nullptr;
						if (realelem) {
							uint8_t m_nOwnerID = *OFFSET(realelem, 0x3, uint8_t*);
							uint16_t m_nID = *OFFSET(realelem, 0x8, uint16_t*);
							uint16_t m_nTime = *OFFSET(realelem, 0xA, uint16_t*);
							uint32_t m_pEntity = *OFFSET(realelem, 0x68, uint32_t*);
							uint16_t m_nSelfPeerID = *OFFSET(cNetSession_mspInst, 0x34, uint16_t*);
							//if(m_nOwnerID != m_nSelfPeerID)
							printf("  %s m_nID %d  m_nTime %d m_pEntity 0x%p, m_nOwnerID %d, m_nSelfPeerID %d\n",
								GetElementType(realelem), m_nID, m_nTime, m_pEntity, m_nOwnerID, m_nSelfPeerID);
						}
					}
				}

			}

			// successor (работаем с raw адресами)
			int next_raw = 0;
			int right_raw = *OFFSET(host_node, 0x0C, int*);
			if (right_raw) {
				// successor = minimum(right)
				int cur_raw = right_raw;
				for (;;) {
					uint8_t* host_cur = EMUPOINTER<uint8_t*>(cur_raw);
					int left_raw = *OFFSET(host_cur, 0x08, int*);
					if (!left_raw) break;
					cur_raw = left_raw;
				}
				next_raw = cur_raw;
			}
			else {
				// climb up until we come from left
				int cur_raw = node_raw;
				int parent_raw = *OFFSET(EMUPOINTER<uint8_t*>(cur_raw), 0x04, int*);
				while (parent_raw) {
					uint8_t* host_parent = EMUPOINTER<uint8_t*>(parent_raw);
					int parent_right_raw = *(int*)OFFSET(host_parent, 0x0C, int*);
					if (cur_raw != parent_right_raw) break;
					cur_raw = parent_raw;
					parent_raw = *OFFSET(host_parent, 0x04, int*);
				}
				next_raw = parent_raw; // может быть header_raw или 0
			}

			node_raw = next_raw;

			if (++iter > size + 8) {
				printf("rb_foreach: abort, iterations > size\n");
				break;
			}
		}
	}

	//printf("CTimer_ms_fTimeStepNonClipped: %f\n", CTimer_ms_fTimeStepNonClipped);

	//if (BTN('T')) // smon
	//{
	//	printf("Enter ppsspp pointer: ");
	//	pMon = EMUPOINTER<void*>(GetPointer());
	//	printf("enter: %p\n", pMon);
	//}

	//if (pMon != nil)
	//	UpdateMon();

	if (cAdhoc_mspInst)
	{
		tLobbyRemoteInfo* pMatchingInfoEntry = EMUPOINTER<tLobbyRemoteInfo*>(*OFFSET(cAdhoc_mspInst, 0x18, uint32_t*));

		tAdhocPlayerData* aMatchingPlayersInfo = OFFSET(cAdhoc_mspInst, 0x484, tAdhocPlayerData*); // мак и ник
		tAdhocMatchingData* aMatchingInfo = OFFSET(cAdhoc_mspInst, 0x5C, tAdhocMatchingData*); // slave массив юзеров
		tAdhocMatchingData* aMatchingInfoRecv = OFFSET(cAdhoc_mspInst, 0x834, tAdhocMatchingData*); // 1st массив юзеров

		if (aMatchingInfoRecv) {
			// print lobbies
			for (int i = 0; i < 7; i++) // по всем лобби // если я хостер и мой стейт 5 в лобби то в aMatchingInfoRecv нет инфо о соседних лобби
			{
				tLobbyRemoteInfo& lobby = aMatchingInfo[i].entry;
				if (aMatchingInfo[i].nState == 0) continue; // ADHOC_PEER_DISCONNECTED free lobby slot
				// state 2 can loin for him
				printf("[%d] aMatchingInfoRecv[i].nState %d \n", i, aMatchingInfo[i].nState);

				//aMatchingInfo[i].nState = 0;

				int nPlayerCount = 0;
				for (int peerIdx = 0; peerIdx < 7; peerIdx++) // по всем пирам в этом лобби
				{
					tAdhocPeerData* pPeer = &lobby.m_nPeersConnInfo[peerIdx];
					if (memcmp(pPeer->macAddr, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0)
						continue;
					nPlayerCount++;
				}
				printf("      players %d\n", nPlayerCount);
			}



			//for (int i = 0; i < 7; i++) // по всем лобби
			//{
			//	tLobbyRemoteInfo& lobby = aMatchingInfoRecv[i].entry;
			//	printf("[%d] aMatchingInfoRecv[i].nState %d \n", i, aMatchingInfoRecv[i].nState);
			//	for (int j = 0; j < 7; j++)
			//	{
			//		//lobby.m_nPeersConnInfo
			//	}
			//}
			printf("\n");
		}

		if (pMatchingInfoEntry) {
			auto& mac = pMatchingInfoEntry->m_nSelfAddr.peerAddr.mac;
			//printf("pMatchingInfoEntry: 0x%p\n", pMatchingInfoEntry);
			//printf("mac: %02X:%02X:%02X:%02X:%02X:%02X\n",
			//	(uint8_t)mac[0], (uint8_t)mac[1], (uint8_t)mac[2],
			//	(uint8_t)mac[3], (uint8_t)mac[4], (uint8_t)mac[5]);

		}

		if (pMon != nil)
			UpdateMon();
		else
			if (cNetSession_mspInst)
			{
				char* m_Timer = OFFSET(cNetSession_mspInst, 0x38, char*);
				float fDeltaS = *OFFSET(m_Timer, 0x1C, float*);
				float fDeltaMs = *OFFSET(m_Timer, 0x20, float*);
				printf("fDeltaS: %f, fDeltaMs: %f\n", fDeltaS, fDeltaMs);
				void* m_fAccTimeStep = OFFSET(TheMPGame, 0xEC, void*);
				void* m_fTimeStep = OFFSET(TheMPGame, 0xE4, void*);
				int& m_nLagValue = *OFFSET(TheMPGame, 0x54, int*);
				printf("m_nLagValue: %d\n", m_nLagValue);
				//if (*(int*)m_fAccTimeStep < 60'000) *(int*)m_fAccTimeStep = 60'000;
				//printf("m_fAccTimeStep: %f %d, m_fTimeStep: %f %d\n", *(float*)m_fAccTimeStep, *(int*)m_fAccTimeStep, *(float*)m_fTimeStep, *(int*)m_fTimeStep);
			}


		//if (BTN('G')) {
		//	if (pMatchingInfoEntry) {
		//		printf("pMatchingInfoEntry (ptr): 0x%p\n", pMatchingInfoEntry);
		//		PrintMacLine(2, "pMatchingInfoEntry.self.mac", pMatchingInfoEntry->m_nSelfAddr.peerAddr.mac);
		//		PrintIndent(2); printf("pMatchingInfoEntry.self.port: %d\n", pMatchingInfoEntry->m_nSelfAddr.peerAddr.port);
		//		PrintIndent(2); printf("pMatchingInfoEntry.self.teamID: %d\n", pMatchingInfoEntry->m_nSelfAddr.nTeamID);

		//		// peers in lobby
		//		for (int pi = 0; pi < 7; ++pi) {
		//			PrintIndent(2);
		//			printf("m_nPeersConnInfo[%d]:\n", pi);
		//			PrintMacLine(6, "mac", pMatchingInfoEntry->m_nPeersConnInfo[pi].macAddr);
		//			PrintIndent(6);
		//			printf("nSelectedPeerModelID: %d\n", pMatchingInfoEntry->m_nPeersConnInfo[pi].nSelectedPeerModelID);
		//			PrintIndent(6);
		//			printf("nTeamID: %d\n", pMatchingInfoEntry->m_nPeersConnInfo[pi].nTeamID);
		//		}

		//		// other entry fields
		//		PrintIndent(2); printf("GameType: %d\n", pMatchingInfoEntry->m_GameType);
		//		PrintIndent(2); printf("GameLocation: %d\n", pMatchingInfoEntry->m_GameLocation);
		//		PrintIndent(2); printf("ScoreLimit: %d\n", pMatchingInfoEntry->m_nScoreLimit);
		//		PrintIndent(2); printf("ScoreCTFLimit: %d\n", pMatchingInfoEntry->m_nScoreCTFLimit);
		//	}
		//	else {
		//		printf("pMatchingInfoEntry == NULL\n");
		//	}
		//	printf("\n\n");


		//	// aMatchingInfo (если есть)
		//	if (aMatchingInfo) {
		//		printf("aMatchingInfo (offset 0x5C): 0x%p\n", aMatchingInfo);
		//		for (int i = 0; i < 7; ++i) {
		//			tAdhocMatchingData& md = aMatchingInfo[i];
		//			printf("m_aMatchingInfo[%d]: 0x%p\n", i, &md);
		//			PrintMacLine(4, "addr", md.addr);
		//			PrintIndent(4); printf("nState: %d\n", md.nState);
		//			PrintIndent(4); printf("nUnkCount: %d\n", md.nUnkCount);

		//			// вложенный entry
		//			tLobbyRemoteInfo& ent = md.entry;
		//			PrintIndent(4); printf("entry.self.peerAddr.mac: ");
		//			PrintMac(ent.m_nSelfAddr.peerAddr.mac); printf("\n");
		//			PrintIndent(4); printf("entry.self.peerAddr.port: %d\n", ent.m_nSelfAddr.peerAddr.port);
		//			PrintIndent(4); printf("entry.self.nTeamID: %d\n", ent.m_nSelfAddr.nTeamID);

		//			// peers в entry
		//			for (int j = 0; j < 7; ++j) {
		//				PrintIndent(6);
		//				printf("entry.m_nPeersConnInfo[%d]: ", j);
		//				PrintMac(ent.m_nPeersConnInfo[j].macAddr); printf("  selModel=%d team=%d\n",
		//					ent.m_nPeersConnInfo[j].nSelectedPeerModelID, ent.m_nPeersConnInfo[j].nTeamID);
		//			}
		//		}
		//	}
		//	else {
		//		printf("aMatchingInfo == NULL\n");
		//	}
		//	printf("\n\n");


		//	// m_aMatchingInfoRecv (recv array) — основной, который у тебя в структуре
		//	if (m_aMatchingInfoRecv) {
		//		printf("m_aMatchingInfoRecv (offset 0x834): 0x%p\n", m_aMatchingInfoRecv);
		//		for (int i = 0; i < 7; ++i) {
		//			tAdhocMatchingData& recv = m_aMatchingInfoRecv[i];
		//			printf("m_aMatchingInfoRecv[%d]:\n", i);
		//			PrintMacLine(4, "addr", recv.addr);
		//			PrintIndent(4); printf("nState: %d\n", recv.nState);
		//			PrintIndent(4); printf("nUnkCount: %d\n", recv.nUnkCount);

		//			// entry внутри recv
		//			tLobbyRemoteInfo& ent = recv.entry;
		//			PrintIndent(4); printf("entry.self.peerAddr.mac: ");
		//			PrintMac(ent.m_nSelfAddr.peerAddr.mac); printf("\n");
		//			PrintIndent(4); printf("entry.self.peerAddr.port: %d\n", ent.m_nSelfAddr.peerAddr.port);
		//			PrintIndent(4); printf("entry.self.nTeamID: %d\n", ent.m_nSelfAddr.nTeamID);
		//			PrintIndent(4); printf("entry.GameType: %d\n", ent.m_GameType);
		//			PrintIndent(4); printf("entry.GameLocation: %d\n", ent.m_GameLocation);
		//			PrintIndent(4); printf("entry.ScoreLimit: %d\n", ent.m_nScoreLimit);
		//			PrintIndent(4); printf("entry.ScoreCTFLimit: %d\n", ent.m_nScoreCTFLimit);

		//			// peers внутри entry
		//			for (int j = 0; j < 7; ++j) {
		//				PrintIndent(6);
		//				printf("entry.m_nPeersConnInfo[%d]: ", j);
		//				PrintMac(ent.m_nPeersConnInfo[j].macAddr); printf("  selModel=%d team=%d\n",
		//					ent.m_nPeersConnInfo[j].nSelectedPeerModelID, ent.m_nPeersConnInfo[j].nTeamID);
		//			}
		//		}
		//	}
		//	else {
		//		printf("m_aMatchingInfoRecv == NULL\n");
		//	}
		//	printf("\n\n");


		//	// m_aMatchingPlayersInfo (игроки) — mac + nickname
		//	if (aMatchingPlayersInfo) {
		//		printf("m_aMatchingPlayersInfo (offset 0x484): 0x%p\n", aMatchingPlayersInfo);
		//		for (int i = 0; i < 7; ++i) {
		//			tAdhocPlayerData& pd = aMatchingPlayersInfo[i];
		//			printf("m_aMatchingPlayersInfo[%d]:\n", i);
		//			PrintMacLine(4, "m_PlayerMacAddr", pd.m_PlayerMacAddr);
		//			PrintStringSafe(4, "m_szPlayerNickname", pd.m_szPlayerNickname, sizeof(pd.m_szPlayerNickname));
		//		}
		//	}
		//	else {
		//		printf("m_aMatchingPlayersInfo == NULL\n");
		//	}

		//	printf("------ end matching info ------\n\n\n\n\n\n\n\n\n\n");
		//}
	}
}

void UpdTest1()
{
	CEntity* pPlayer = FindPlayerPed();
	//printf("pPlayer: 0x%p\n", pPlayer);
	if (!pPlayer)
		return;
	RpClump* pClump = EMUPOINTER<RpClump*>(pPlayer->m_urwObject.m_rpClump);
	//printf("rwobj type id: %d %s\n", rwo->type, rwo->type == rpATOMIC ? "atomic" : "clump");
	//printf("pClump: 0x%p %s\n", pClump, GetRwObjectDescByType(pClump->object.type));


	RwLLLink* head = &pClump->atomicList.link;
	//debug("head : 0x%p\n", head); // field clump
	RpAtomic a;
	assert(((uint8_t*)&a) == ((uint8_t*)&a.inElementGroupLink - 0x1C)); // stru test

	int i = 0;
	//for (RwLinkList* link = EMUPOINTER<RwLinkList*>(clump->atomicList.link.next); link; link = EMUPOINTER<RwLinkList*>(link->link.next)) // wrong looping
	for (RwLLLink* link = EMUPOINTER<RwLLLink*>(head->next); link != head; link = EMUPOINTER<RwLLLink*>(link->next)) // FORLIST
	{
		RpAtomic* atomic = RpAtomic_fromClump(link); // FORLIST
		//printf("ATOMIC!!! [%d] : 0x%p   lnk 0x%p\n", i++, atomic, link);
		//printf("atomic: 0x%p %s\n", atomic, GetRwObjectDescByType(atomic->object.object.type));
		RpGeometry* geo = EMUPOINTER<RpGeometry*>(atomic->geometry);
		//float s = GetRandomFloatInc(0.5f, 2.5f);
		float s = 1.2f;
		//geo->msPspGeometry.scale[0] = s;
		//geo->msPspGeometry.scale[1] = s;
		//geo->msPspGeometry.scale[2] = s;
		//geo->msPspGeometryMesh.matID -= -1;
		//geo->msPspGeometry.numStrips = 5;
		//geo->msPspGeometry.pos[0] = 2.3f;
		//geo->msPspGeometry.pos[1] = 2.3f;
		//geo->msPspGeometry.pos[2] = 2.3f;
		//geo->msPspGeometryMesh.numTriangles = 0;
		static bool _=0;
		if(!_){_^=1;

			//sPspGeometry* header = (sPspGeometry*)(geo+1); // old geo stru
			sPspGeometry* header = &geo->msPspGeometry;
			sPspGeometryMesh* strip = (sPspGeometryMesh*)(header+1);
			uint8_t* after = (uint8_t*)(strip+1);
			//printf("geo->msPspGeometry: 0x%X\n", &geo->msPspGeometry);
			printf("geo->msPspGeometry: 0x%X\n", header);
			printf("geo->sPspGeometryMesh: 0x%X\n", strip);
			printf("after: 0x%X\n", after);
			printf("offset %d   0x%X\n", header->offset, OFFSET(header, header->offset, uint8_t*));
		}
	}



	//{
	//	for (int32_t i = CPools_ms_pPedPool->m_nSize - 1; i >= 0; i--)
	//	{
	//		if (CPools_GetSlotIsFree(CPools_ms_pPedPool, i)) { continue; }
	//		CPed* p = (CPed*)CPools_GetSlot(CPools_ms_pPedPool, i, 3344);
	//		if (p) {
	//			int32_t mindex = p->CPhysical.CEntity.m_modelIndex;
	//			CBaseModelInfo* mi = GetModelInfo(mindex);
	//			printf("ped[%d]: 0x%p, mi: 0x%p\n", p->CPhysical.CEntity.m_modelIndex, p, mi);
	//			// test code
	//			{
	//				int8_t& b1D8 = *OFFSET(p, 0x1D8, int8_t*);
	//				SWAP_BIT(b1D8, 3);
	//				//bool IsDBY = b1D8 & BIT(3);
	//				//b1D8 = IsDBY ? (b1D8 & (~BIT(3))) : (IsDBY | BIT(3));
	//			}
	//		}
	//	}
	//}
}

tCombatMove* GetCombatMovie(uint32_t n)
{
	uint8_t* pCombatMoves = EMUPOINTER<uint8_t*>(*EMUPOINTER<uint32_t*>(0x08BAA5B0));
	uint8_t* pMovesData = EMUPOINTER<uint8_t*>(*OFFSET(pCombatMoves, 0x8, uint32_t*));
	uint32_t numMoves = *OFFSET(pCombatMoves, 0x8 + 0x4, uint32_t*); // 0x68
	myassert(n < numMoves);
	return (tCombatMove*)(pMovesData + (0x40 * n));

	//for (uint32_t i = 0; i < numMoves; i++) {
	//	uint8_t* pCurr = pMovesData + (0x40 * i);
	//	char* pName = (char*)(pCurr + 0x33);
	//}
}

void LogH()
{
	CEntity* e = FindPlayerPed();
	if (e)
		printf("%f %f %f\n", e->CPlaceable.m_pMat.pos.x, e->CPlaceable.m_pMat.pos.y, e->CPlaceable.m_pMat.pos.z);
}

//#define LOG_MENU_
//#define LOG_MENU2_
void LogMenu()
{
	system("cls");

	struct tList {
		uint8_t* pStart;
		uint8_t* pEnd;
		uint8_t* pCap;
	};
	static_assert(sizeof(tList) == 4*3, "sizeof(tList)");

	auto DumpErrors = [&]() {
		uint32_t* pArr = EMUPOINTER<uint32_t*>(0x08B8A830);
		for (int32_t i = 0; i < 9; i++) {
			printf("\"%s\"\n", EMUPOINTER<char*>(pArr[i]));
		}
	};
	//DumpErrors();

	auto cMenuItemVT = [&](uint32_t vt) {
		switch (vt)
		{
			case 0x08BA6098:
				return "cMenuItemBase";
			case 0x08BA8018:
				return "cMenuItem";
			case 0x08BA4FE8:
				return "cMenuItemScrolling";
			case 0x08BA5758:
				return "cMenuItemRadioIcons";
			case 0x08BA59C0:
				return "cMenuItemImage";
			case 0x08BA5FA8:
				return "cMenuItemMultiState";
			case 0x08BA6020:
				return "cMenuItemCustomMap";
			case 0x08BA61D8:
				return "cMenuItemSlider";
			case 0x08BA8850:
				return "cMenuItemMultiplayer";
			case 0x08BA8A68:
				return "cMenuItemControlPad";
			case 0x08BA8AE0:
				return "cMenuItemCustomTracks";
			case 0x0:
				return "NULLPTR";
		}

		return "UNKNOWN";
	};

	auto Log_cMenuItem = [&](uint8_t* pPspThis, int32_t mode) {
		if (!pPspThis)
			return;
		uint8_t* pThis = EMUPOINTER<uint8_t*>(pPspThis);
		uint32_t& vt = *OFFSET(pThis, 0x24, uint32_t*);
		printf("    cMenuItem pPspThis 0x%p type %s\n", pPspThis, cMenuItemVT(vt)); //------------------------------------------

		uint8_t* pStrStart = EMUPOINTER<uint8_t*>(*OFFSET(pThis, 0, uint8_t**)); // ptr to 1st list field (ptr to start)
		uint32_t& startX = *OFFSET(pThis, 0xC, uint32_t*);
		uint32_t& startY = *OFFSET(pThis, 0x10, uint32_t*);
		uint32_t& sizeX = *OFFSET(pThis, 0x14, uint32_t*);
		uint32_t& sizeY = *OFFSET(pThis, 0x18, uint32_t*);
		float& f_field_1C = *OFFSET(pThis, 0x1C, float*);
		bool& bShouldRender = *OFFSET(pThis, 0x20, bool*);
		tList* m_aTriggerActions = OFFSET(pThis, 0x64, tList*); // массив векторов указателей
		uint8_t nItemSize = 4; // void*

		//startX = rand() % 500;
		//startY = rand() % 500;
		//bShouldRender = rand() % 2;
		static int32_t nCnt = 0;
		//if (nCnt++ == 1 || nCnt == 3) {
		//	bShouldRender = false;
		//	printf("    gfhfgghfh type %s\n", cMenuItemVT(vt));
		//}

		if (vt == 0x08BA5FA8 && *OFFSET(pThis, 0xC4, uint8_t*) > 1) // cMenuItemMultiState
		{
			uint8_t& nCount = *OFFSET(pThis, 0xC4, uint8_t*);
			uint8_t* pStart = EMUPOINTER<uint8_t*>(*OFFSET(pThis, 0xB8, uint8_t**));
			uint8_t* pEnd = EMUPOINTER<uint8_t*>(*OFFSET(pThis, 0xB8 + 4, uint8_t**));
			uint8_t nCountE = (pEnd - pStart) / 12;

			//printf("cMenuItemMultiState count %d\n", nCount);
			//printf("ps 0x%p  pe 0x%p\n", pStart, pEnd);

			uint8_t* pNode = pStart;
			for (int32_t i = 0; i < nCount; i++) { // vecs
				uint8_t* pStrStart = EMUPOINTER<uint8_t*>(*OFFSET(pNode, 0x0, uint8_t**));
				//printf("   str %s\n", pStrStart);
				pNode += 12;
			}
		}
		else if (vt == 0x08BA61D8) // cMenuItemSlider
		{
			float& f = *OFFSET(pThis, 0xB8, float*);
			int32_t& bc = *OFFSET(pThis, 0xBC, int32_t*);
			int32_t& c0 = *OFFSET(pThis, 0xC0, int32_t*);
			int8_t& c4 = *OFFSET(pThis, 0xC4, int8_t*);
			//printf("%f %d %d %d\n", f, bc, c0, c4);
			//f = 0.2f;
			//bc = c0 = 128;
			//c0 = 5;
		}

		if (mode == 2) { // navs buttons
			if (vt == 0x08BA5FA8) // multistate
			{
				int32_t& m_nHorizontal = *OFFSET(pThis, 0x58, int32_t*);
				printf("%d %d  H %d\n", startX, startY, m_nHorizontal);
				m_nHorizontal = 4; // 0def 1left 2centre 4right
				//int d = 20;
				//startX = 480-d;
				//startY = 272-d;
				//bShouldRender = false;
			}
		}

		tList* pTNode = m_aTriggerActions;
		for (int i = 0; i < 7; i++) { // массив
			uint8_t* pStart = EMUPOINTER<uint8_t*>(pTNode->pStart);
			uint8_t* pEnd = EMUPOINTER<uint8_t*>(pTNode->pEnd);
#ifdef LOG_MENU2_
			printf("    0x%p\n", pTNode->pStart);
#endif

			int l = (pEnd - pStart) / nItemSize;
			for (int j = 0; j < l; j++) {
				uint8_t* pEl = *(uint8_t**)(pStart + (nItemSize * j));
				uint8_t* pBind = EMUPOINTER<uint8_t*>(pEl);
				uint8_t* pStrStart = EMUPOINTER<uint8_t*>(*OFFSET(pBind, 0x4, uint8_t**)); // ptr to 1st list field (ptr to start)
				uint8_t* pStrStart2 = EMUPOINTER<uint8_t*>(*OFFSET(pBind, 0x10, uint8_t**));
#ifdef LOG_MENU2_
				printf("  pStrStart %s\n", pStrStart);
				printf("  pStrStart2 %s\n", pStrStart2);
				printf("    el 0x%p\n", pEl);
#endif

			}



			++pTNode;
		}

#ifdef LOG_MENU_
		printf("    NAME %s\n", pStrStart);
		printf("    vt %s\n", cMenuItemVT(vt));
		printf("\n");
#endif
	};

	auto Log_cMenuItems = [&](uint8_t* pPspThis, int32_t mode){
		if (!pPspThis)
			return;
		uint8_t* pThis = EMUPOINTER<uint8_t*>(pPspThis);
		//printf("cMenuItems pPspThis 0x%p\n", pPspThis);

		uint8_t* pStrStart = EMUPOINTER<uint8_t*>(*OFFSET(pThis, 0, uint8_t**)); // ptr to 1st list field (ptr to start)
		uint8_t* pStrStart2 = EMUPOINTER<uint8_t*>(*OFFSET(pThis, 0x18, uint8_t**));
		uint8_t* m_vecItems_Start = EMUPOINTER<uint8_t*>(*OFFSET(pThis, 0x24, uint8_t**)); // ptr to 1st list field
		uint8_t* m_vecItems_End = EMUPOINTER<uint8_t*>(*OFFSET(pThis, 0x28, uint8_t**)); // ptr to 2st list field
		uint32_t& field_30 = *OFFSET(pThis, 0x30, uint32_t*);
		uint8_t nItemSize = 4; // void*

		//pStrStart[0] = '_';
		//pStrStart2[0] = '_';
#ifdef LOG_MENU_
		printf("  NAME %s\n", pStrStart);
		printf("  NAME2 %s\n", pStrStart2);
		printf("  m_vecItems Size %d\n", (m_vecItems_End - m_vecItems_Start) / nItemSize);
#endif

		uint8_t* node = m_vecItems_Start;
		uint32_t i = 0;
		while (node != m_vecItems_End)
		{
			uint8_t* pItem = (uint8_t*)*(uint32_t*)node;
#ifdef LOG_MENU_
			printf("  [%d] 0x%p %d  (0x%p)\n", i++, pItem, field_30 == (uint32_t)pItem, field_30);
#endif
			//field_30 = 0;
			node += nItemSize;
		}

		node = m_vecItems_Start;
		while (node != m_vecItems_End)
		{
			uint8_t* pItem = (uint8_t*)*(uint32_t*)node;
			Log_cMenuItem(pItem, mode);
			node += nItemSize;
		}
	};

	uint8_t* pMasterPSP = *OFFSET(FrontEndMenuManager, 0, uint8_t**);
	uint8_t* m_vecScreens_StartPSP = EMUPOINTER<uint8_t*>(*OFFSET(FrontEndMenuManager, 4, uint8_t**));
	uint8_t* m_vecScreens_EndPSP = EMUPOINTER<uint8_t*>(*OFFSET(FrontEndMenuManager, 8, uint8_t**));
	uint8_t* m_vecMenuNavigationHints_StartPSP = EMUPOINTER<uint8_t*>(*OFFSET(FrontEndMenuManager, 16, uint8_t**));
	uint8_t* m_vecMenuNavigationHints_EndPSP = EMUPOINTER<uint8_t*>(*OFFSET(FrontEndMenuManager, 20, uint8_t**));
	uint8_t nItemSize = 4; // void*

	Log_cMenuItems(pMasterPSP, 0);
	//printf("0x%p\n", pMasterPSP);

	uint8_t* node = m_vecScreens_StartPSP;
	while (node != m_vecScreens_EndPSP)
	{
		uint8_t* pItem = (uint8_t*)*(uint32_t*)node;
		Log_cMenuItems(pItem, 1);
		node += nItemSize;
	}

	node = m_vecMenuNavigationHints_StartPSP;
	while (node != m_vecMenuNavigationHints_EndPSP)
	{
		uint8_t* pItem = (uint8_t*)*(uint32_t*)node;
		Log_cMenuItems(pItem, 2);
		node += nItemSize;
	}
}

#define LOG_(a)
void DumpFonts(const char* filename) {
	std::ofstream out(filename);
	if (!out.is_open()) {
		printf("Не удалось открыть файл для записи\n");
		return;
	}

	uint8_t** tFontDefData = (uint8_t**)fontdef;
	for (int32_t i = 0; i < 3; i++) {
		uint8_t* tFontDef = EMUPOINTER<uint8_t*>(tFontDefData[i]);
		if (!tFontDef) continue;

		// ---- Дамп полей cFontSystem ----
		out << "font\n";
		LOG_(out << "# FontSystem[" << i << "] m_nCharCount\n";)
		out << *(uint16_t*)(tFontDef + 0x00) << "\n";

		LOG_(out << "# FontSystem[" << i << "] m_nExtendedCharCount\n";)
		out << *(uint16_t*)(tFontDef + 0x02) << "\n";

		LOG_(out << "# FontSystem[" << i << "] m_nMonospaceWidth\n";)
		out << *(uint16_t*)(tFontDef + 0x04) << "\n";

		LOG_(out << "# FontSystem[" << i << "] m_nFontHeightY\n";)
		out << *(uint16_t*)(tFontDef + 0x06) << "\n";

		//LOG_(out << "# FontSystem[" << i << "] m_pCharTable (address)\n";)
		//out << *(uint32_t*)(tFontDef + 0x08) << "\n";  // указатель

		//LOG_(out << "# FontSystem[" << i << "] m_pExtendedCharTable (address)\n";)
		//out << *(uint32_t*)(tFontDef + 0x0C) << "\n";

		LOG_(out << "# FontSystem[" << i << "] m_nFontStyle\n";)
		out << (int)*(uint8_t*)(tFontDef + 0x10) << "\n";

		LOG_(out << "# FontSystem[" << i << "] m_nTxdSlot\n";)
		out << *(uint32_t*)(tFontDef + 0x14) << "\n";

		LOG_(out << "# FontSystem[" << i << "] m_nTexWidth\n";)
		out << *(uint16_t*)(tFontDef + 0x18) << "\n";

		LOG_(out << "# FontSystem[" << i << "] m_nTexHeight\n";)
		out << *(uint16_t*)(tFontDef + 0x1A) << "\n";

		// m_CurrentColor (CRGBA) — 4 байта
		LOG_(out << "# FontSystem[" << i << "] m_CurrentColor (RGBA)\n";)
		uint32_t color = *(uint32_t*)(tFontDef + 0x1C);
		out << "0x" << std::hex << color << std::dec << "\n";

		LOG_(out << "# FontSystem[" << i << "] m_fScale\n";)
		out << *(float*)(tFontDef + 0x20) << "\n";

		LOG_(out << "# FontSystem[" << i << "] m_nPropMode\n";)
		out << (int)*(uint8_t*)(tFontDef + 0x24) << "\n";

		LOG_(out << "# FontSystem[" << i << "] m_nCentreMode\n";)
		out << *(uint32_t*)(tFontDef + 0x28) << "\n";

		// m_sTextureName (строка, максимум 15 байт)
		LOG_(out << "# FontSystem[" << i << "] m_sTextureName\n";)
		out << (char*)(tFontDef + 0x2C) << "\n";

		LOG_(out << "# FontSystem[" << i << "] m_bOutlineOn\n";)
		out << (int)*(uint8_t*)(tFontDef + 0x3B) << "\n";

		LOG_(out << "# FontSystem[" << i << "] m_ColourBorder (RGBA)\n";)
		uint32_t border = *(uint32_t*)(tFontDef + 0x3C);
		out << "0x" << std::hex << border << std::dec << "\n";

		LOG_(out << "# FontSystem[" << i << "] m_bBackgroundOn\n";)
		out << (int)*(uint8_t*)(tFontDef + 0x40) << "\n";

		LOG_(out << "# FontSystem[" << i << "] m_ColourBackground (RGBA)\n";)
		uint32_t bg = *(uint32_t*)(tFontDef + 0x41); // смещение 0x41?
		out << "0x" << std::hex << bg << std::dec << "\n";

		LOG_(out << "# FontSystem[" << i << "] m_nNewLineAdd\n";)
		out << *(uint32_t*)(tFontDef + 0x48) << "\n";
		out << "end\n";

		// ---- Дамп таблицы глифов (m_pCharTable) ----
		uint8_t* charTable = EMUPOINTER<uint8_t*>(*(uint32_t*)(tFontDef + 0x08));
		uint16_t charCount = *(uint16_t*)(tFontDef + 0x00); // m_nCharCount

		out << "glyp\n";
		if (charTable && charCount > 0)
		{
			for (uint16_t j = 0; j < charCount; ++j) {
				uint8_t* glyph = charTable + j * 0x0E; // размер sGlyphInfo = 0x0E
				LOG_(out << "# CharTable[" << j << "] m_nLeftOffset\n";)
				out << *(int16_t*)(glyph + 0x00) << "\n";
				LOG_(out << "# CharTable[" << j << "] m_nWidth\n";)
				out << *(int16_t*)(glyph + 0x02) << "\n";
				LOG_(out << "# CharTable[" << j << "] m_nRightOffset\n";)
				out << *(int16_t*)(glyph + 0x04) << "\n";
				LOG_(out << "# CharTable[" << j << "] m_nHeight\n";)
				out << *(int16_t*)(glyph + 0x06) << "\n";
				LOG_(out << "# CharTable[" << j << "] m_wchar\n";)
				out << *(uint16_t*)(glyph + 0x08) << "\n";
				LOG_(out << "# CharTable[" << j << "] m_nStartX\n";)
				out << *(uint16_t*)(glyph + 0x0A) << "\n";
				LOG_(out << "# CharTable[" << j << "] m_nStartY\n";)
				out << *(uint16_t*)(glyph + 0x0C) << "\n";
			}
		}
		out << "end\n";

		// ---- Дамп расширенной таблицы глифов (m_pExtendedCharTable) ----
		uint8_t* extTable = EMUPOINTER<uint8_t*>(*(uint32_t*)(tFontDef + 0x0C));
		uint16_t extCount = *(uint16_t*)(tFontDef + 0x02); // m_nExtendedCharCount

		out << "glext\n";
		if (extTable && extCount > 0)
		{
			for (uint16_t j = 0; j < extCount; ++j) {
				uint8_t* glyph = extTable + j * 0x0E;
				LOG_(out << "# ExtendedCharTable[" << j << "] m_nLeftOffset\n";)
				out << *(int16_t*)(glyph + 0x00) << "\n";
				LOG_(out << "# ExtendedCharTable[" << j << "] m_nWidth\n";)
				out << *(int16_t*)(glyph + 0x02) << "\n";
				LOG_(out << "# ExtendedCharTable[" << j << "] m_nRightOffset\n";)
				out << *(int16_t*)(glyph + 0x04) << "\n";
				LOG_(out << "# ExtendedCharTable[" << j << "] m_nHeight\n";)
				out << *(int16_t*)(glyph + 0x06) << "\n";
				LOG_(out << "# ExtendedCharTable[" << j << "] m_wchar\n";)
				out << *(uint16_t*)(glyph + 0x08) << "\n";
				LOG_(out << "# ExtendedCharTable[" << j << "] m_nStartX\n";)
				out << *(uint16_t*)(glyph + 0x0A) << "\n";
				LOG_(out << "# ExtendedCharTable[" << j << "] m_nStartY\n";)
				out << *(uint16_t*)(glyph + 0x0C) << "\n";
			}
		}
		out << "end\n";
	}

	out.close();
	printf("Дамп записан в %s\n", filename);
}

void LogFont()
{
	float& fracX = *EMUPOINTER<float*>(0x08BB1F20);
	float& fracY = *EMUPOINTER<float*>(0x08BB1F24);
	//fracX = fracY = 0.0f;

	//DumpFonts("C:\\fontspsp.dat"); return;

	struct sGlyphInfo
	{
		int16_t m_nLeftOffset;
		int16_t m_nWidth;
		int16_t m_nRightOffset;
		int16_t m_nHeight;
		int16_t m_wchar; // recheck
		int16_t m_nU; // recheck
		int16_t m_nV; // recheck
	};
	static_assert(sizeof(sGlyphInfo) == 0xE, "sizeof(sGlyphInfo) == 0xE");

	uint8_t** tFontDefData = (uint8_t**)fontdef;
	for (int32_t i = 0; i < 3; i++) {
		uint8_t* tFontDef = EMUPOINTER<uint8_t*>(tFontDefData[i]);
		uint16_t& numTab = *(uint16_t*)(tFontDef + 0x00);
		uint8_t* m_pCharTable = EMUPOINTER<uint8_t*>(*OFFSET(tFontDef, 0x8, uint8_t**));
		sGlyphInfo* pGlyph = (sGlyphInfo*)m_pCharTable;
		for (int32_t j = 0; j < numTab; j++)
		{
			int dt = 1;

			//pGlyph[j].m_nWidth--; // да уже
			//pGlyph[j].m_nHeight--; // да тоньше
			//pGlyph[j].m_nLeftOffset--; // визуально едет вправо
			//pGlyph[j].m_nRightOffset--; // визуально едет влево
			//pGlyph[j].m_nU--; // визуально едет вправо
			//pGlyph[j].m_nV--; // визуально едет вниз

			pGlyph[j].m_nLeftOffset++;
			pGlyph[j].m_nRightOffset--;
		}
		continue;

		//uint16_t& f0 = *(uint16_t*)(m_pCharTable + 0x00);
		//uint16_t& f2 = *(uint16_t*)(m_pCharTable + 0x02);
		//uint16_t& f4 = *(uint16_t*)(m_pCharTable + 0x04);
		//uint16_t& f6 = *(uint16_t*)(m_pCharTable + 0x06);
		//uint16_t& f8 = *(uint16_t*)(m_pCharTable + 0x08); // wchar
		//uint16_t& fA = *(uint16_t*)(m_pCharTable + 0x0A);
		//uint16_t& fC = *(uint16_t*)(m_pCharTable + 0x0C);

		//int dt = 1;
		////f2 += dt;
		////f6 += dt;
		////fA += dt;
		////fC += dt;
		////*(uint16_t*)tFontDef = 0;
		//fA = fC = 0; // неа
		//f0 = f4 = 0;
		//f2 = f6 = 0;
		//f8 = 0;
		////memset(m_pCharTable, 0, 0xE**(uint16_t*)tFontDef);

		////f0+=5; // m_nLeftOffset
		////f2+=5; // m_nWidth
		////f4+=5; // m_nRightOffset
		////f6+=5; // m_nHeight
		////f8+=5; // smth pad
		////fA +=5; // 
		////fC +=5; // 

		////tFontDef[6] = rand() % 255;
		////tFontDef[6] = 0;
		////uint16_t& w = *(uint16_t*)(tFontDef + 0x18);
		////uint16_t& h = *(uint16_t*)(tFontDef + 0x1A);
		////w = rand() % 65200;
		////h = rand() % 65200;
		////printf("%s\n", (char*)tFontDef + 0x2C);
	}
}

void LogCustomTracks()
{
	struct tList {
		uint8_t* pStart;
		uint8_t* pEnd;
		uint8_t* pCap;
	};
	static_assert(sizeof(tList) == 4 * 3, "sizeof(tList)");

	uint8_t* pThis = CustomSoundTrack;
	uint8_t* vec2_field_18_Start = EMUPOINTER<uint8_t*>(*OFFSET(pThis, 0x18, uint8_t**)); // e8
	uint8_t* vec2_field_18_End = EMUPOINTER<uint8_t*>(*OFFSET(pThis, 0x18+4, uint8_t**));
	uint8_t* node = vec2_field_18_Start;
	while (node != vec2_field_18_End)
	{
		//printf("###### %s\n", EMUPOINTER<char*>(*(int32_t*)(node + 4)));
		printf("##\n");
		node += 8;
	}
}

void LogRadar()
{
	//uint8_t* gRadarTex = EMUPOINTER<uint8_t*>(0x08BD5AF0);
	uint8_t* gRadarTex = EMUPOINTER<uint8_t*>(0x0989738C);
	for (int32_t i = 0; i < 100; i++)
	{
		//printf("%d   0x%p\n", i, ((int32_t*)gRadarTex)[i]);
	}

	uint8_t* pThis = TheRadar;
	CVuVector m_vec_field_1AD0 = *OFFSET(pThis, 0x1AD0, CVuVector*);
	CVuVector m_vecPos_field_1AE0 = *OFFSET(pThis, 0x1AE0, CVuVector*);
	CVuVector mypos = FindPlayerPed()->CPlaceable.m_pMat.pos;
	//m_vec_field_1AD0.x = m_vec_field_1AD0.y = m_vec_field_1AD0.z = 0.0f;
	printf("m_vec_field_1AD0: %f %f %f\n", m_vec_field_1AD0.x, m_vec_field_1AD0.y, m_vec_field_1AD0.z);
	printf("m_vecPos_field_1AE0: %f %f %f\n", m_vecPos_field_1AE0.x, m_vecPos_field_1AE0.y, m_vecPos_field_1AE0.z);
	printf("m_vec_field_1AD0: %f %f %f\n", mypos.x, mypos.y, mypos.z);
}

void LogMemoryTest()
{
	int _ = 16;
	printf("\n");

	for (int32_t i = 0; i < _; i++) {
		uint32_t* pMem = EMUPOINTER<uint32_t*>(0x08BA1D80);
		printf("car %d 0x%X\n", pMem[i], pMem[i]);
	}
	printf("\n");

	for (int32_t i = 0; i < _; i++) {
		uint32_t* pMem = EMUPOINTER<uint32_t*>(0x08BA1DBC);
		printf("boat %d 0x%X\n", pMem[i], pMem[i]);
	}
	printf("\n");

	for (int32_t i = 0; i < _; i++) {
		uint32_t* pMem = EMUPOINTER<uint32_t*>(0x08BA1DE8);
		printf("heli %d 0x%X\n", pMem[i], pMem[i]);
	}
	printf("\n");

	for (int32_t i = 0; i < _; i++) {
		uint32_t* pMem = EMUPOINTER<uint32_t*>(0x08BA1E04);
		printf("ped %d 0x%X\n", pMem[i], pMem[i]);
	}
	printf("\n");
}

void LogPath()
{
	printf("path!!!\n");
	struct t12 {
		int a1[2]; // ptr
		uint8_t a2[2]; // num
		uint8_t a3[2]; // pad
	};
	static_assert(sizeof(t12) == 12, "s");
	uint8_t* pThis = gpThePaths;
	t12* p = (t12*)(pThis + 0x28);
	//for (int32_t i = 0; i < 50*50; i++)
	int max = 0;
	for (int32_t i = 0; i < 500; i++)
	{
		//if (max < p[i].a2[0] || max < p[i].a2[1]) max = p[i].a2[0] > p[i].a2[1] ? p[i].a2[0] : p[i].a2[1];
		if (max < p[i].a2[0]) max = p[i].a2[0];
		if (max < p[i].a2[1]) max = p[i].a2[1];
		//printf("%d 0x%p\n", i, p[i]);
	}
	printf("max %d\n", max); // 16
	printf("%d\n", *(int*)(pThis + 0x7560));
	//memset(p, 0, 50*50*12);
}

void Test1()
{
	char* sr = EMUPOINTER<char*>(0x08BADB44);
	for (int i = 0; i < 4; i++)
	{
		sr[i] = 0;
	}

	for (int32_t i = CPools_ms_pPedPool->m_nSize - 1; i >= 0; i--)
	{
		if (CPools_GetSlotIsFree(CPools_ms_pPedPool, i)) { continue; }
		CEntity* p = (CEntity*)CPools_GetSlot(CPools_ms_pPedPool, i, 3344);
		if (p) {
			int32_t mindex = p->m_modelIndex;

			//CBaseModelInfo* mi = GetModelInfo(mindex);
			if (mindex == 146) // phc
			{
				{
					*EMUPOINTER<int*>(0x08A113F8) = 0x00'00'00'00; // CTimer::ms_fTimeStep = (v1 * CTimer::ms_fTimeScale) / 5898240.0;
					*EMUPOINTER<int*>(0x08A11480) = 0x00'00'00'00; // CTimer::ms_fTimeStep
					*EMUPOINTER<int*>(0x08A6A3C4) = 0x00'00'00'00; // CTimer::ms_fTimeStep
					*EMUPOINTER<int*>(0x08A6A474) = 0x00'00'00'00; // CTimer::ms_fTimeStep
					*EMUPOINTER<int*>(0x08A6A514) = 0x00'00'00'00; // CTimer::ms_fTimeStep
					*EMUPOINTER<float*>(0x08BB3B5C) = 1.0f;
				}

				CVector2D* m_vecAnimMoveDelta = OFFSET(p, 0x318, CVector2D*);
				printf("146!!!! 0x%p   0x%p  %d\n", p, PSPTRANSLATE(p), !!(p->CE_flags_B&2));
				//p->bUsesCollision = true;
				//*OFFSET(p, 0x6F4, char*) = 0; // 0xF0
				printf("entity status: %d %s\n", GetEntityStatus(p), GetEntityStatusStr(p));
				printf("pos %f %f %f\n", p->CPlaceable.m_pMat.pos.x, p->CPlaceable.m_pMat.pos.y, p->CPlaceable.m_pMat.pos.z);
				printf("anim %f %f  0x%p\n", m_vecAnimMoveDelta->x, m_vecAnimMoveDelta->y, PSPTRANSLATE(m_vecAnimMoveDelta));
				printf("%d\n", !!(*OFFSET(p, 0x000001C8, char*)&1));
				//m_vecAnimMoveDelta->x = 5.0f;
				//m_vecAnimMoveDelta->y = 5.0f;
			}
		}
	}
}

void Test2()
{
	float& ms_fWheelAngle = *EMUPOINTER<float*>(0x08BAAC38);
	printf("%f\n", ms_fWheelAngle);
	//ms_fWheelAngle = rand() % 3;
}

void DumpCombatMovesToFile(CCombatMoves* pMoves, const char* filename)
{
	FILE* f = std::fopen(filename, "w");
	if (!f) return;

	enum
	{
		NONE,
		SECTION_A, // CCombatMoves,   count
		SECTION_B, // CCombatMoveData_A_A
		SECTION_C, // CCombatMove
		SECTION_D, // CCombatMoveData_B_A
		SECTION_E, // CCombatMove_A
		SECTION_F, // CCombatMove_A_A
		SECTION_G, // CCombatMove_A_B
		SECTION_H, // CCombatMove_B
		SECTION_I, // CCombatMove_B_A
	};

	struct CSectionLayout {
		int32_t structSize;
		std::map<size_t, size_t> skips;
	};

	static const CSectionLayout layout[] = {
		/*NONE*/      { 0, {} },
		/*SECTION_A*/ { sizeof(CCombatMoves), {
			{ offsetof(CCombatMoves, m_DataA) + offsetof(CCombatMoveData_A, m_aArr),   sizeof(void*) },
			{ offsetof(CCombatMoves, m_MovesData) + offsetof(CCombatMoveData,   m_aMoves), sizeof(void*) },
			{ offsetof(CCombatMoves, m_DataB) + offsetof(CCombatMoveData_B, m_aArr),   sizeof(void*) },
			{ offsetof(CCombatMoves, m_pEntity), sizeof(void*) },
		}},
		/*SECTION_B*/ { sizeof(CCombatMoveData_A_A), { } },
		/*SECTION_C*/ { sizeof(CCombatMove), {
			{ offsetof(CCombatMove, m_aArr_A), sizeof(void*) },
			{ offsetof(CCombatMove, m_aArr_B), sizeof(void*) },
		}},
		/*SECTION_D*/ { sizeof(CCombatMoveData_B_A), { } },
		/*SECTION_E*/ { sizeof(CCombatMove_A), {
			{ offsetof(CCombatMove_A, m_aArr_A), sizeof(void*) },
			{ offsetof(CCombatMove_A, m_aArr_B), sizeof(void*) },
		}},
		/*SECTION_F*/ { sizeof(CCombatMove_A_A), { } },
		/*SECTION_G*/ { sizeof(CCombatMove_A_B), { } },
		/*SECTION_H*/ { sizeof(CCombatMove_B), {
			{ offsetof(CCombatMove_B, m_aArr), sizeof(void*) },
		}},
		/*SECTION_I*/ { sizeof(CCombatMove_B_A), { } },
	};

	auto emit = [&](const CSectionLayout& L, const uint8_t* base) {
		size_t caret = 0, wrote = 0, skipSum = 0;
		for (auto& kv : L.skips) skipSum += kv.second;

		while (caret < (size_t)L.structSize) {
			auto it = L.skips.find(caret);
			if (it != L.skips.end()) {
				caret += it->second;
				continue;
			}
			std::fprintf(f, " 0x%02X", base[caret]);
			caret++; wrote++;
		}
		assert(wrote == (size_t)L.structSize - skipSum && "POD stream size mismatch");
	};

	// SECTION_A - CCombatMoves
	std::fprintf(f, "id1\n[0]");
	emit(layout[SECTION_A], (const uint8_t*)pMoves);
	std::fprintf(f, "\nend\n\n");

	// SECTION_B - CCombatMoveData_A_A
	std::fprintf(f, "id2\n");
	{
		CCombatMoveData_A_A** arr = EMUPOINTER<CCombatMoveData_A_A**>(pMoves->m_DataA.m_aArr);
		for (int i = 0; i < pMoves->m_DataA.m_nCount; i++) {
			CCombatMoveData_A_A* entry = EMUPOINTER<CCombatMoveData_A_A*>(arr[i]);
			std::fprintf(f, "[%d]", i);
			emit(layout[SECTION_B], (const uint8_t*)entry);
			std::fprintf(f, "\n");
		}
	}
	std::fprintf(f, "end\n\n");

	// SECTION_C - CCombatMove
	std::fprintf(f, "id3\n");
	CCombatMove* moves = EMUPOINTER<CCombatMove*>(pMoves->m_MovesData.m_aMoves);
	for (int i = 0; i < pMoves->m_MovesData.m_nMoveCount; i++) {
		std::fprintf(f, "[%d]", i);
		emit(layout[SECTION_C], (const uint8_t*)&moves[i]);
		std::fprintf(f, "\n");
	}
	std::fprintf(f, "end\n\n");

	// SECTION_D - CCombatMoveData_B_A
	std::fprintf(f, "id4\n");
	{
		CCombatMoveData_B_A* arr = EMUPOINTER<CCombatMoveData_B_A*>(pMoves->m_DataB.m_aArr);
		for (int i = 0; i < pMoves->m_DataB.m_nCount; i++) {
			std::fprintf(f, "[%d]", i);
			emit(layout[SECTION_D], (const uint8_t*)&arr[i]);
			std::fprintf(f, "\n");
		}
	}
	std::fprintf(f, "end\n\n");

	// SECTION_E - CCombatMove_A
	std::fprintf(f, "id5\n");
	for (int i = 0; i < pMoves->m_MovesData.m_nMoveCount; i++) {
		CCombatMove_A* arrA = EMUPOINTER<CCombatMove_A*>(moves[i].m_aArr_A);
		for (int j = 0; j < moves[i].m_nCount_A; j++) {
			std::fprintf(f, "[%d][%d]", i, j);
			emit(layout[SECTION_E], (const uint8_t*)&arrA[j]);
			std::fprintf(f, "\n");
		}
	}
	std::fprintf(f, "end\n\n");

	// SECTION_F - CCombatMove_A_A
	std::fprintf(f, "id6\n");
	for (int i = 0; i < pMoves->m_MovesData.m_nMoveCount; i++) {
		CCombatMove_A* arrA = EMUPOINTER<CCombatMove_A*>(moves[i].m_aArr_A);
		for (int j = 0; j < moves[i].m_nCount_A; j++) {
			if (!arrA[j].m_aArr_A) {
				std::fprintf(f, "[%d][%d][0] null\n", i, j);
				continue;
			}
			CCombatMove_A_A* subA = EMUPOINTER<CCombatMove_A_A*>(arrA[j].m_aArr_A);
			for (int k = 0; k < 1; k++) {
				std::fprintf(f, "[%d][%d][%d]", i, j, k);
				emit(layout[SECTION_F], (const uint8_t*)&subA[k]);
				std::fprintf(f, "\n");
			}
		}
	}
	std::fprintf(f, "end\n\n");

	// SECTION_G - CCombatMove_A_B
	std::fprintf(f, "id7\n");
	for (int i = 0; i < pMoves->m_MovesData.m_nMoveCount; i++) {
		CCombatMove_A* arrA = EMUPOINTER<CCombatMove_A*>(moves[i].m_aArr_A);
		for (int j = 0; j < moves[i].m_nCount_A; j++) {
			if (!arrA[j].m_aArr_B) {
				std::fprintf(f, "[%d][%d][0] null\n", i, j);
				continue;
			}
			CCombatMove_A_B* subB = EMUPOINTER<CCombatMove_A_B*>(arrA[j].m_aArr_B);
			for (int k = 0; k < 1; k++) {
				std::fprintf(f, "[%d][%d][%d]", i, j, k);
				emit(layout[SECTION_G], (const uint8_t*)&subB[k]);
				std::fprintf(f, "\n");
			}
		}
	}
	std::fprintf(f, "end\n\n");

	// SECTION_H - CCombatMove_B
	std::fprintf(f, "id8\n");
	for (int i = 0; i < pMoves->m_MovesData.m_nMoveCount; i++) {
		CCombatMove_B* arrB = EMUPOINTER<CCombatMove_B*>(moves[i].m_aArr_B);
		for (int j = 0; j < moves[i].m_nCount_B; j++) {
			std::fprintf(f, "[%d][%d]", i, j);
			emit(layout[SECTION_H], (const uint8_t*)&arrB[j]);
			std::fprintf(f, "\n");
		}
	}
	std::fprintf(f, "end\n\n");

	// SECTION_I - CCombatMove_B_A
	std::fprintf(f, "id9\n");
	for (int i = 0; i < pMoves->m_MovesData.m_nMoveCount; i++) {
		CCombatMove_B* arrB = EMUPOINTER<CCombatMove_B*>(moves[i].m_aArr_B);
		for (int j = 0; j < moves[i].m_nCount_B; j++) {
			CCombatMove_B_A* arrBA = EMUPOINTER<CCombatMove_B_A*>(arrB[j].m_aArr);
			for (int k = 0; k < arrB[j].m_nCount; k++) {
				std::fprintf(f, "[%d][%d][%d]", i, j, k);
				emit(layout[SECTION_I], (const uint8_t*)&arrBA[k]);
				std::fprintf(f, "\n");
			}
		}
	}
	std::fprintf(f, "end\n\n");

	std::fclose(f);
}

void DumpCombatStatsToFile(CCombatStats* pStats, const char* filename)
{
	FILE* f = std::fopen(filename, "w");
	if (!f) return;

	int numStats = pStats->m_nNumStats;

	enum
	{
		NONE,
		SECTION_A, // CCombatStats,  count
		SECTION_B, // CCombatStat
		SECTION_C, // CCombatStat_A
		SECTION_D, // CCombatStat_B
		SECTION_E, // CCombatStat_B_A
	};

	struct CSectionLayout {
		int32_t structSize;
		std::map<size_t, size_t> skips; // offset -> size, пропуск (например указателей)
	};

	// индекс таблицы = значение enum
	static const CSectionLayout layout[] = {
		/*NONE*/      { 0, {} },
		/*SECTION_A*/ { sizeof(CCombatStats),    { { offsetof(CCombatStats,   m_aStats), sizeof(void*) } } },
		/*SECTION_B*/ { sizeof(CCombatStat),     { { offsetof(CCombatStat,    m_aArr_A), sizeof(void*) },
												   { offsetof(CCombatStat,    m_aArr_B), sizeof(void*) } } },
		/*SECTION_C*/ { sizeof(CCombatStat_A),   { } },
		/*SECTION_D*/ { sizeof(CCombatStat_B),   { { offsetof(CCombatStat_B,  m_pData),  sizeof(void*) } } },
		/*SECTION_E*/ { sizeof(CCombatStat_B_A), { } },
	};

	// печатает POD-байты структуры, пропуская диапазоны из таблицы
	auto emit = [&](const CSectionLayout& L, const uint8_t* base) {
		size_t caret = 0, wrote = 0, skipSum = 0;
		for (auto& kv : L.skips) skipSum += kv.second;

		while (caret < (size_t)L.structSize) {
			auto it = L.skips.find(caret);
			if (it != L.skips.end()) {
				caret += it->second;
				continue;
			}
			std::fprintf(f, " 0x%02X", base[caret]);
			caret++; wrote++;
		}
		assert(wrote == (size_t)L.structSize - skipSum && "POD stream size mismatch");
	};

	// SECTION_A - CCombatStats
	std::fprintf(f, "id1\n[0]");
	emit(layout[SECTION_A], (const uint8_t*)pStats);
	std::fprintf(f, "\nend\n\n");

	// SECTION_B - CCombatStat
	std::fprintf(f, "id2\n");
	for (int i = 0; i < numStats; i++) {
		CCombatStat* pStat = &EMUPOINTER<CCombatStat*>(pStats->m_aStats)[i];
		std::fprintf(f, "[%d]", i);
		emit(layout[SECTION_B], (const uint8_t*)pStat);
		std::fprintf(f, "\n");
	}
	std::fprintf(f, "end\n\n");

	// SECTION_C - CCombatStat_A
	std::fprintf(f, "id3\n");
	for (int i = 0; i < numStats; i++) {
		CCombatStat* pStat = &EMUPOINTER<CCombatStat*>(pStats->m_aStats)[i];
		CCombatStat_A* a = EMUPOINTER<CCombatStat_A*>(pStat->m_aArr_A);
		for (int j = 0; j < pStat->m_nCount_A; j++) {
			std::fprintf(f, "[%d][%d]", i, j);
			emit(layout[SECTION_C], (const uint8_t*)&a[j]);
			std::fprintf(f, "\n");
		}
	}
	std::fprintf(f, "end\n\n");

	// SECTION_D - CCombatStat_B
	std::fprintf(f, "id4\n");
	for (int i = 0; i < numStats; i++) {
		CCombatStat* pStat = &EMUPOINTER<CCombatStat*>(pStats->m_aStats)[i];
		CCombatStat_B* arr = EMUPOINTER<CCombatStat_B*>(pStat->m_aArr_B);
		for (int j = 0; j < pStat->m_nCount_B; j++) {
			std::fprintf(f, "[%d][%d]", i, j);
			emit(layout[SECTION_D], (const uint8_t*)&arr[j]);
			std::fprintf(f, "\n");
		}
	}
	std::fprintf(f, "end\n\n");

	// SECTION_E - CCombatStat_B_A
	std::fprintf(f, "id5\n");
	for (int i = 0; i < numStats; i++) {
		CCombatStat* pStat = &EMUPOINTER<CCombatStat*>(pStats->m_aStats)[i];
		CCombatStat_B* arr = EMUPOINTER<CCombatStat_B*>(pStat->m_aArr_B);
		for (int j = 0; j < pStat->m_nCount_B; j++) {
			CCombatStat_B_A* ba = EMUPOINTER<CCombatStat_B_A*>(arr[j].m_pData);
			std::fprintf(f, "[%d][%d]", i, j);
			emit(layout[SECTION_E], (const uint8_t*)ba);
			std::fprintf(f, "\n");
		}
	}
	std::fprintf(f, "end\n\n");

	std::fclose(f);
}

void DumpCombat2F()
{
	//return;
	const char* pMovesFile = "COMBATMOVES.DAT";
	const char* pStatsFile = "COMBATSTATS.DAT";


	CCombatMoves* pMoves = (CCombatMoves*)gpFightMoves;
	CCombatStats* pStats = (CCombatStats*)gpFightStats;

#if 1
	DumpCombatMovesToFile(pMoves, pMovesFile);
	DumpCombatStatsToFile(pStats, pStatsFile);
	printf("DumpCombat done\n");
	Sleep(50000000);
#endif

	for (int32_t i = 0; i < pMoves->m_MovesData.m_nMoveCount; i++)
	{
		CCombatMove* pMoves2 = &EMUPOINTER<CCombatMove*>(pMoves->m_MovesData.m_aMoves)[i];
		//pMoves2->ptr_field_20 = 0; // +=32 _881E290
		//pMoves2->ptr_field_24 = 0;

		//printf("%d\n", pStats->m_nNumStats);
	}


	{
		CCombatMove* moves = EMUPOINTER<CCombatMove*>(pMoves->m_MovesData.m_aMoves);
		for (int32_t i = 0; i < pMoves->m_MovesData.m_nMoveCount; i++)
		{
			CCombatMove* mv = &moves[i];

			CCombatMove_B* arrB = EMUPOINTER<CCombatMove_B*>(mv->m_aArr_B);
			for (int32_t j = 0; j < mv->m_nCount_B; j++)
			{
				CCombatMove_B* mvB = &arrB[j];

				CCombatMove_B_A* arrBA = EMUPOINTER<CCombatMove_B_A*>(mvB->m_aArr);
				for (int32_t k = 0; k < mvB->m_nCount; k++)
				{
					CCombatMove_B_A* mvBA = &arrBA[k];
					// у CCombatMove_B_A нет count — терминальный уровень
					(void)mvBA;
				}

				mvB->m_nCount = 0;
			}

			mv->m_nCount_A = 0; // 0 руками махает
			mv->m_nCount_B = 0; // 0 нет ударов
		}

		pMoves->m_DataA.m_nCount = 0;
		pMoves->m_MovesData.m_nMoveCount = 0;
		pMoves->m_DataB.m_nCount = 0;
	}

}

void LogCombat()
{
	CEntity* pPed = FindPlayerPed();
	if (!pPed) return;
	//uint8_t* pMyCombatMgr = OFFSET(pPed, 0x7E0, uint8_t*); // sizeof(0x2C) // unused for playerped??
	uint8_t* m_nPlayerCombatInfo = EMUPOINTER<uint8_t*>(*OFFSET(pPed, 0xCDC, uint32_t*)); // sizeof(0x18B0)
	uint8_t* m_nPlayerCombatMgr = OFFSET(m_nPlayerCombatInfo, 0x4, uint8_t*); // sizeof(0x94)
	//printf("m_fStamina: %f\n", *OFFSET(m_nPlayerCombatMgr, 0x0, float*));
	//*OFFSET(m_nPlayerCombatMgr, 0x0, float*) = 0.0f;
	uint8_t& index = *OFFSET(m_nPlayerCombatMgr, 0x8, uint8_t*);
	uint8_t& flagsA = *OFFSET(m_nPlayerCombatMgr, 0x9, uint8_t*);
	uint8_t& flagsB = *OFFSET(m_nPlayerCombatMgr, 0xA, uint8_t*);
	uint8_t& flagsC = *OFFSET(m_nPlayerCombatMgr, 0xB, uint8_t*);
	//flagsB = 0;
	//index = 1; // kek walk
	//printf("index: %d\n", index);
	//printf("flags: %d %d %d\n", flagsA, flagsB, flagsC);
	uint32_t pfakemgr = OFFSET(*OFFSET(pPed, 0xCDC, uint32_t*), 0x4, uint32_t);
	printf("current movie %d %s 0x%p\n", index, GetCombatMovie(index)->name, OFFSET(pfakemgr, 0x8, uint32_t));
	printf("fs: %f\n", *OFFSET(m_nPlayerCombatMgr, 0x0, float*));

	uint8_t* pCapPed = EMUPOINTER<uint8_t*>(*OFFSET(pPed, 0x81C, uint32_t*));
	if (pCapPed) {
		//printf("capped: 0x%p\n", pCapPed);
		uint8_t* pCapPedCombatMgr = OFFSET(pCapPed, 0x7E0, uint8_t*); // sizeof(0x2C) // unused for playerped??
		//printf("capindex: %d\n", *OFFSET(pCapPedCombatMgr, 0x8, uint8_t*));
		//printf("capflags: %d %d %d\n", *OFFSET(pCapPedCombatMgr, 0x9, uint8_t*), *OFFSET(pCapPedCombatMgr, 0xA, uint8_t*), *OFFSET(pCapPedCombatMgr, 0xB, uint8_t*));
	}



	return; //---------!!
	uint8_t* m_CombatManager = OFFSET(pPed, 0x7E0, uint8_t*); // sizeof(0x2C)
	uint8_t* m_pPlayerCombat = OFFSET(pPed, 0xCDC, uint8_t*); // sizeof(0x2C)
	//float& m_fStamina = *OFFSET(m_CombatManager, 0x0, float*);
	//m_fStamina = 0;
	//*(int*)m_pPlayerCombat = 0; // crash
	uint8_t* m_nPlayerCombat2 = EMUPOINTER<uint8_t*>(*(int*)m_pPlayerCombat); // sizeof(0x18B0)
	uint8_t* m_nPlayerCombat3 = OFFSET(m_nPlayerCombat2, 0x4, uint8_t*); // sizeof(0x94)
	//memset(m_nPlayerCombat3, 0, 0x24);

	//printf("pPed: 0x%p\n", pPed);
	//printf("m_CombatManager.m_fStamina: %f  0x%p\n", m_fStamina, &m_fStamina);
	//printf("m_CombatManager.m_fStamina: 0x%p\n", OFFSET(m_CombatManager, 0x0, float*));
	printf("PC: 0x%p\n", m_CombatManager);
	printf("PLC: 0x%p\n", m_nPlayerCombat3);
	printf("m_fStamina: %f\n", *OFFSET(m_nPlayerCombat3, 0x0, float*));
	*OFFSET(m_nPlayerCombat3, 0x0, float*) = 0.0f;
	//printf("\n");
}


bool quit = false;
bool poll = false;
void MainUpd()
{
	//LogCombat();
	//LogH();

	if(poll){
		if((GetAsyncKeyState(VK_SHIFT) & 0x8000) == 0)
		system("cls");
		//LogRadar();
		LogCombat();
		//Test1();
		//Test2();
	}

	if (BTN('T'))
	{
		DumpCombat2F();
		LogCombat();
		Test2();
		poll^=1;
		LogMenu();
		//LogCustomTracks();
		//LogRadar();
		LogFont();
		LogPath();
		//LogMemoryTest();
		//TestModelInfo();
		Sleep(500);
	}

	if (BTN('H'))
	{
		OnBtn();
		Sleep(500);
	}


	//char* pdma = EMUPOINTER<char*>(0x08BAFB5C);
	//pdma[0] = rand() % 2;
	//pdma[1] = rand() % 2;
	//pdma[2] = rand() % 2;
	//pdma[3] = rand() % 2;
	//if (bPatchMp) {
	//	bPatchMp = false;
	//	PatchNoMPCars(); // once, load state restore patch!!
	//	if (BTN('R'))
	//		quit = true;
	//}
}

void PluginInit()
{
	U_SetCurrentDirectory();
	InitConsole();
	ModelInfoExt::Init("C:\\PSPVCSMODELS.txt");
}

void PluginLoop()
{
	quit = BTN('Q');
	//if (BTN('R'))
	if (!PPSSPP_BASE) // todo OnLoadGame/State Event!!!!
	{ // temp hack to find region
		//Sleep(1);
		//Sleep(500);
		std::vector<MemoryRegion> regions = FindRegions(0, MEM_MAPPED, 0, 0);
		//printf("total find: %d\n", regions.size());
		for (int32_t i = 0; i < regions.size(); i++) {
			//printf("%d  0x%X  %d\n", i, regions[i].baseAddress, regions[i].size);
			if ((i - 3) < regions.size() && regions[i].size == 32505856 && regions[i + 1].size == 32505856 && regions[i + 2].size == 2097152) {
				PPSSPP_BASE = (uintptr_t)regions[i].baseAddress + ELF_BASE_OFFSET;
				break;
			}
		}
	}
	if (!PPSSPP_BASE)
		return;
	//printf("find: 0x%X\n", PPSSPP_BASE);
	if (strcmp(EMUPOINTER<char*>(0x08BB153C), "ULUS10160") != 0) { // ppsspp disable asserts
		//printf("assert failed\n");
		return;
	}
	static bool once = false;
	if (!once) {
		once = true;
		printf("PPSSPP_BASE: 0x%p\n", PPSSPP_BASE);
	}

	//Once();
	//UpdPad();
	UpdMP();  //-----------------------------
	MainUpd();
	//UpdTest1();

	//printf("%s\n", PSPPOINTER(0x08BB153C));
	//printf("%s\n", PSPPOINTER(0x08BAD5C0));
	Sleep(1);
}

DWORD CALLBACK ThreadEntry(LPVOID)
{
	if (!BTN(VK_SHIFT))
		return TRUE;

	if (BTN(VK_CONTROL))
		bPatchMp = true;

	//WaitElf();
	PluginInit();
	while (!quit)
	{
		PluginLoop();
		Sleep(1);
	}
	return TRUE;
}

BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hinstDLL);
		CreateThread(NULL, 0, ThreadEntry, NULL, 0, NULL);
	}
	return TRUE;
}