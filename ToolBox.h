///////////////////////////////////
// ToolBox - Useful Code         //
// David Anson (http://dlaa.me/) //
///////////////////////////////////


#if !defined(TOOL_BOX_HEADER)
#define TOOL_BOX_HEADER

// Do not use "new" or "delete" in any of the inlined code below (excluding templates)
// so that we can avoid having those allocations tracked by ToolBoxDebug

#include <windows.h>
#include <TCHAR.h>
// Some environments do not have an assert.h file, but do have an ASSERT(...)
// macro defined
#if defined(ASSERT)
#define assert(e) ASSERT(e)
#else  // defined(ASSERT)
#include <assert.h>
#define ASSERT(e) assert(e)
#endif  // defined(ASSERT)

// C_ASSERT() can be used to perform many compile-time assertions: type sizes,
// field offsets, etc.  (From VC++'s WinNT.h)
#if !defined(C_ASSERT)
#define C_ASSERT(e) typedef char __C_ASSERT__[(e)?1:-1]
// An assertion failure results in error C2118: negative subscript.
#endif // !defined(C_ASSERT)

// Provide a verify macro for all environments
#if !defined(VERIFY)
#if defined(DEBUG) || defined(_DEBUG)
#define VERIFY(e) ASSERT(e)
#else  // defined(DEBUG) || defined(_DEBUG)
#define VERIFY(e) ((void)(e))
#endif  // defined(DEBUG) || defined(_DEBUG)
#endif  // !defined(VERIFY)

// Macro to simplify determining the number of elements in an array (do *not*
// use this macro for pointers)
#define ARRAY_LENGTH(x) (sizeof(x)/sizeof((x)[0]))

#endif  // !defined(TOOL_BOX_HEADER)
