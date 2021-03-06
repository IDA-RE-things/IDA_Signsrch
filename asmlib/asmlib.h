
/*************************** asmlib.h ***************************************
* Author:        Agner Fog
* Date created:  2003-12-12
* Last modified: 2011-08-21
* Project:       asmlib.zip
* Source URL:    www.agner.org/optimize
*
* Description:
* Header file for the asmlib function library.
* This library is available in many versions for different platforms.
* See asmlib-instructions.pdf for details.
*
* Copyright 2003 - 2011 by Agner Fog. 
* GNU General Public License http://www.gnu.org/licenses/gpl.html
*****************************************************************************/
// KW:
#pragma once
#if defined(_WIN64)
#pragma comment(lib, "alibcof64.lib")
#else
#pragma comment(lib, "alibcof32.lib")
#endif
// Had to add __cdecl to each function

#ifndef ASMLIB_H
#define ASMLIB_H

/***********************************************************************
Define compiler-specific types and directives
***********************************************************************/

// Define type size_t
#ifndef _SIZE_T_DEFINED
#include "stddef.h"
#endif

// Define integer types with known size: int32_t, uint32_t, int64_t, uint64_t.
// If this doesn't work then insert compiler-specific definitions here:
#if defined(__GNUC__) || (defined(_MSC_VER) && _MSC_VER >= 1600)
  // Compilers supporting C99 or C++0x have stdint.h defining these integer types
  #include <stdint.h>
  #define INT64_SUPPORTED // Remove this if the compiler doesn't support 64-bit integers
#elif defined(_MSC_VER)
  // Older Microsoft compilers have their own definition
  typedef signed   __int16  int16_t;
  typedef unsigned __int16 uint16_t;
  typedef signed   __int32  int32_t;
  typedef unsigned __int32 uint32_t;
  typedef signed   __int64  int64_t;
  typedef unsigned __int64 uint64_t;
  #define INT64_SUPPORTED // Remove this if the compiler doesn't support 64-bit integers
#else
  // This works with most compilers
  typedef signed   short int  int16_t;
  typedef unsigned short int uint16_t;
  typedef signed   int        int32_t;
  typedef unsigned int       uint32_t;
  typedef long long           int64_t;
  typedef unsigned long long uint64_t;
  #define INT64_SUPPORTED // Remove this if the compiler doesn't support 64-bit integers
#endif


// Turn off name mangling
#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************
Function prototypes, memory and string functions
***********************************************************************/
void * __cdecl A_memcpy (void * dest, const void * src, size_t count); // Copy count bytes from src to dest
void * __cdecl A_memmove(void * dest, const void * src, size_t count); // Same as memcpy, allows overlap between src and dest
void * __cdecl A_memset (void * dest, int c, size_t count);            // Set count bytes in dest to (char)c
size_t __cdecl GetMemcpyCacheLimit(void);                              // Data blocks bigger than this will be copied uncached by memcpy and memmove
void   __cdecl SetMemcpyCacheLimit(size_t);                            // Change limit in GetMemcpyCacheLimit
size_t __cdecl GetMemsetCacheLimit(void);                              // Data blocks bigger than this will be stored uncached by memset
void   __cdecl SetMemsetCacheLimit(size_t);                            // Change limit in GetMemsetCacheLimit
char * __cdecl A_strcat (char * dest, const char * src);               // Concatenate strings dest and src. Store result in dest
char * __cdecl A_strcpy (char * dest, const char * src);               // Copy string src to dest
size_t __cdecl A_strlen (const char * str);                            // Get length of zero-terminated string
int    __cdecl A_strcmp (const char * a, const char * b);              // Compare strings. Case sensitive
int    __cdecl A_stricmp (const char *string1, const char *string2);   // Compare strings. Case insensitive for A-Z only
char * __cdecl A_strstr (char * haystack, const char * needle);        // Search for substring in string
void   __cdecl A_strtolower(char * string);                            // Convert string to lower case for A-Z only
void   __cdecl A_strtoupper(char * string);                            // Convert string to upper case for a-z only
size_t __cdecl A_substring(char * dest, const char * source, size_t pos, size_t len); // Copy a substring for source into dest
size_t __cdecl A_strspn (const char * str, const char * set);          // Find span of characters that belong to set
size_t __cdecl A_strcspn(const char * str, const char * set);          // Find span of characters that don't belong to set
size_t __cdecl strCountInSet(const char * str, const char * set);      // Count characters that belong to set
size_t __cdecl strcount_UTF8(const char * str);                        // Counts the number of characters in a UTF-8 encoded string

/***********************************************************************
Function prototypes, miscellaneous functions
***********************************************************************/
uint32_t __cdecl A_popcount(uint32_t x);                               // Count 1-bits in 32-bit integer
int    __cdecl RoundD (double x);                                      // Round to nearest or even
int    __cdecl RoundF (float  x);                                      // Round to nearest or even
int    __cdecl InstructionSet(void);                                   // Tell which instruction set is supported
char * __cdecl ProcessorName(void);                                    // ASCIIZ text describing microprocessor
void   __cdecl CpuType(int * vendor, int * family, int * model);       // Get CPU vendor, family and model
size_t __cdecl DataCacheSize(int level);                               // Get size of data cache
void   __cdecl A_DebugBreak(void);                                     // Makes a debug breakpoint
#ifdef INT64_SUPPORTED
   uint64_t __cdecl ReadTSC(void);                                     // Read microprocessor internal clock (64 bits)
#else
   uint32_t __cdecl ReadTSC(void);                                     // Read microprocessor internal clock (only 32 bits supported by compiler)
#endif
void __cdecl cpuid_ex (int abcd[4], int eax, int ecx);                 // call CPUID instruction
static inline void cpuid_abcd (int abcd[4], int eax) {
   cpuid_ex(abcd, eax, 0);}

#ifdef __cplusplus
}  // end of extern "C"

// Define overloaded versions if compiling as C++

static inline int Round (double x) {   // Overload name Round
   return RoundD(x);}
static inline int Round (float  x) {   // Overload name Round
   return RoundF(x);}
static inline const char * A_strstr(const char * haystack, const char * needle) {
   return A_strstr((char*)haystack, needle);} // Overload A_strstr with const char * version

#endif // __cplusplus


/***********************************************************************
Function prototypes, integer division functions
***********************************************************************/

// Turn off name mangling
#ifdef __cplusplus
extern "C" {
#endif

void __cdecl setdivisori32(int buffer[2], int d);                      // Set divisor for repeated division
int __cdecl dividefixedi32(const int buffer[2], int x);                // Fast division with previously set divisor
void __cdecl setdivisoru32(uint32_t buffer[2], uint32_t d);            // Set divisor for repeated division
uint32_t __cdecl dividefixedu32(const uint32_t buffer[2], uint32_t x); // Fast division with previously set divisor

// Test if emmintrin.h is included and __m128i defined
#if defined(__GNUC__) && defined(_EMMINTRIN_H_INCLUDED) && !defined(__SSE2__)
#error Please compile with -sse2 or higher 
#endif

#if defined(_INCLUDED_EMM) || (defined(_EMMINTRIN_H_INCLUDED) && defined(__SSE2__))
#define VECTORDIVISIONDEFINED

// define vector division functions for 16 bit signed and unsigned integers
void __cdecl setdivisorV8i16(__m128i buf[2], int16_t d);               // Set divisor for repeated division
__m128i __cdecl dividefixedV8i16(const __m128i buf[2], __m128i x);     // Fast division with previously set divisor
void __cdecl setdivisorV8u16(__m128i buf[2], uint16_t d);              // Set divisor for repeated division
__m128i __cdecl dividefixedV8u16(const __m128i buf[2], __m128i x);     // Fast division with previously set divisor

// define vector division functions for 32 bit signed and unsigned integers
void __cdecl setdivisorV4i32(__m128i buf[2], int32_t d);               // Set divisor for repeated division
__m128i __cdecl dividefixedV4i32(const __m128i buf[2], __m128i x);     // Fast division with previously set divisor
void __cdecl setdivisorV4u32(__m128i buf[2], uint32_t d);              // Set divisor for repeated division
__m128i __cdecl dividefixedV4u32(const __m128i buf[2], __m128i x);     // Fast division with previously set divisor
#endif

#ifdef __cplusplus
}  // end of extern "C"

// Define classes and operator '/' for fast division with fixed divisor
class div_i32;
class div_u32;
static inline int32_t  operator / (int32_t  x, div_i32 const &D);
static inline uint32_t operator / (uint32_t x, div_u32 const & D);

class div_i32 {                                                // Signed 32 bit integer division
public:
div_i32() {buffer[0] = buffer[1] = 0;}                         // Default constructor
div_i32(int d) {setdivisor(d);}                                // Constructor with divisor
void setdivisor(int d) {setdivisori32(buffer, d);}             // Set divisor
protected:
   int buffer[2];                                              // Internal memory
friend int32_t operator / (int32_t x, div_i32 const & D);
};
static inline int32_t operator / (int32_t x, div_i32 const &D){// Overloaded operator '/'
   return dividefixedi32(D.buffer, x);}

class div_u32 {                                                // Unsigned 32 bit integer division
public:
div_u32() {buffer[0] = buffer[1] = 0;}                         // Default constructor
div_u32(uint32_t d) {setdivisor(d);}                           // Constructor with divisor
void setdivisor(uint32_t d) {setdivisoru32(buffer, d);}        // Set divisor
protected:
   uint32_t buffer[2];                                         // Internal memory
friend uint32_t operator / (uint32_t x, div_u32 const & D);
};
static inline uint32_t operator / (uint32_t x, div_u32 const & D) { // Overloaded operator '/'
   return dividefixedu32(D.buffer, x);}

#ifdef VECTORDIVISIONDEFINED
// Define classes and operator '/' for fast division of vectors with fixed divisor
class div_v8i16;   // vector of 8 signed   integers of 16 bits
class div_v8u16;   // vector of 8 unsigned integers of 16 bits
class div_v4i32;   // vector of 4 signed   integers of 32 bits
class div_v4u32;   // vector of 4 unsigned integers of 32 bits
static inline __m128i operator / (__m128i x, div_v8i16 const & D);
static inline __m128i operator / (__m128i x, div_v8u16 const & D);
static inline __m128i operator / (__m128i x, div_v4i32 const & D);
static inline __m128i operator / (__m128i x, div_v4u32 const & D);

class div_v8i16 {                                              // vector of 8 signed integers of 16 bits
public:
   div_v8i16() {buffer[0] = buffer[1] = _mm_set1_epi16(0);}    // default constructor
   div_v8i16(int16_t d) {setdivisor(d);}                       // constructor with divisor
   void setdivisor(int16_t d) {setdivisorV8i16(buffer, d);}    // set divisor
protected:
   __m128i buffer[2];                                          // Internal memory
friend __m128i operator / (__m128i x, div_v8i16 const & D);
};
static inline __m128i operator / (__m128i x, div_v8i16 const &D){// Overloaded operator '/'
   return dividefixedV8i16(D.buffer, x);}

class div_v8u16 {                                              // vector of 8 unsigned integers of 16 bits
public:
   div_v8u16() {buffer[0] = buffer[1] = _mm_set1_epi16(0);}    // default constructor
   div_v8u16(uint16_t d) {setdivisor(d);}                      // constructor with divisor
   void setdivisor(uint16_t d) {setdivisorV8u16(buffer, d);}   // set divisor
protected:
   __m128i buffer[2];                                          // Internal memory
friend __m128i operator / (__m128i x, div_v8u16 const & D);
};
static inline __m128i operator / (__m128i x, div_v8u16 const &D){// Overloaded operator '/'
   return dividefixedV8u16(D.buffer, x);}

class div_v4i32 {                                              // vector of 4 signed integers of 32 bits
public:
   div_v4i32() {buffer[0] = buffer[1] = _mm_set1_epi32(0);}    // default constructor
   div_v4i32(int32_t d) {setdivisor(d);}                       // constructor with divisor
   void setdivisor(int32_t d) {setdivisorV4i32(buffer, d);}    // set divisor
protected:
   __m128i buffer[2];                                          // Internal memory
friend __m128i operator / (__m128i x, div_v4i32 const & D);
};
static inline __m128i operator / (__m128i x, div_v4i32 const &D){// Overloaded operator '/'
   return dividefixedV4i32(D.buffer, x);}

class div_v4u32 {                                              // vector of 4 unsigned integers of 32 bits
public:
   div_v4u32() {buffer[0] = buffer[1] = _mm_set1_epi32(0);}    // default constructor
   div_v4u32(uint32_t d) {setdivisor(d);}                      // constructor with divisor
   void setdivisor(uint32_t d) {setdivisorV4u32(buffer, d);}   // set divisor
protected:
   __m128i buffer[2];                                          // Internal memory
friend __m128i operator / (__m128i x, div_v4u32 const & D);
};
static inline __m128i operator / (__m128i x, div_v4u32 const &D){// Overloaded operator '/'
   return dividefixedV4u32(D.buffer, x);}

// Support for vector classes defined in Intel's dvec.h
#ifdef _DVEC_H_INCLUDED
static inline Is32vec4 operator / (Is32vec4 const &x, div_v4i32 const &D){
   return (__m128i)x / D;}
static inline Iu32vec4 operator / (Iu32vec4 const &x, div_v4u32 const &D){
   return (__m128i)x / D;}
static inline Is16vec8 operator / (Is16vec8 const &x, div_v8i16 const &D){
   return (__m128i)x / D;}
static inline Iu16vec8 operator / (Iu16vec8 const &x, div_v8u16 const &D){
   return (__m128i)x / D;}
#endif // _DVEC_H_INCLUDED

#endif // VECTORDIVISIONDEFINED

#endif // __cplusplus

#endif // ASMLIB_H
