//////////////////////////////////////////
// ToolBox - Useful Code                //
// David Anson (DavidAns@Microsoft.com) //
//////////////////////////////////////////


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

// Class to allow access to a string as an ANSI string
class AnsiString
	{
	public:
	AnsiString(const wchar_t* const psWide, const wchar_t pcEndOfString = L'\0');
	AnsiString(const char* const psAnsi, const char pcEndOfString = '\0');
	~AnsiString();
	operator char*()
		{
		if(0 != m_psAnsi)
			{
			return m_psAnsi;
			}
		else
			{
			return "";
			}
		}
	private:
	AnsiString(const AnsiString&);  // Not supported
	AnsiString& operator=(const AnsiString&);  // Not supported
	char* m_psAnsi;
	};

// Class to safely handle interactions with a DLL
class LibraryLoader
	{
	public:
	LibraryLoader(const TCHAR* const psLibraryFileName)
		{
		m_hInstLibrary = 0;
		Load(psLibraryFileName);
		}
	~LibraryLoader()
		{
		Unload();
		}
	bool Load(const TCHAR* const psLibraryFileName)
		{
		Unload();
		m_hInstLibrary = (0 != psLibraryFileName) ? LoadLibrary(psLibraryFileName) : 0;
		return LoadSucceeded();
		}
	bool LoadSucceeded() const
		{
		return (m_hInstLibrary != 0);
		}
	void Unload()
		{
		if(0 != m_hInstLibrary)
			{
			FreeLibrary(m_hInstLibrary);
			m_hInstLibrary = 0;
			}
		}
	FARPROC GetProcedureAddress(const TCHAR* const psProcedureName) const
		{
		FARPROC fpReturn = 0;
		if(0 != m_hInstLibrary)
			{
#ifdef UNDER_CE
			fpReturn = GetProcAddress(m_hInstLibrary, psProcedureName);
#else // UNDER_CE
			fpReturn = GetProcAddress(m_hInstLibrary, AnsiString(psProcedureName));
#endif // UNDER_CE
			}
		return fpReturn;
		}
	private:
	LibraryLoader(const LibraryLoader&);  // Not supported
	LibraryLoader& operator=(const LibraryLoader&);  // Not supported
	HINSTANCE m_hInstLibrary;
	};

// Class to manage an indeterminate number of things
// NOTE: NOT safe for classes that overload operator= or use copy-
// constructors (because of this class's use of memcpy)
template <class T> class GrowableThingCollection
	{
	public:
	// Constructor/destructor/operator overloads
	GrowableThingCollection(int iGrowSize = 10)
		{
		InitializeCriticalSection(&m_csData);
		InitializeCriticalSection(&m_csModify);
		m_ptArray = 0;
		m_iSlotsUsed = 0;
		m_iSlotsAllocated = 0;
		ASSERT(0 < iGrowSize);
		m_iGrowSize = (0 < iGrowSize) ? iGrowSize : 1;
		m_uiLockCount = 0;
		}
	GrowableThingCollection(const GrowableThingCollection& rgtc)
		{
		InitializeCriticalSection(&m_csData);
		InitializeCriticalSection(&m_csModify);
		CopyAnotherGrowableThingCollection(rgtc);
		}
	virtual ~GrowableThingCollection()
		{
		ASSERT(0 == m_uiLockCount);
		if(0 != m_ptArray)
			{
			LocalFree(m_ptArray);
			}
		/*
		m_ptArray = 0;
		m_iSlotsUsed = 0;
		m_iSlotsAllocated = 0;
		m_iGrowSize = 0;
		m_uiLockCount = 0;
		*/
		DeleteCriticalSection(&m_csModify);
		DeleteCriticalSection(&m_csData);
		}
	GrowableThingCollection& operator=(const GrowableThingCollection& rgtc)
		{
		if(0 != m_ptArray)
			{
			LocalFree(m_ptArray);
			}
		CopyAnotherGrowableThingCollection(rgtc);
		return *this;
		}
	// Methods that modify the collection
	virtual bool AddThing(const T t)
		{
		bool bSuccess = false;
		EnterCriticalSection(&m_csModify);
		EnterCriticalSection(&m_csData);
		if(0 == m_uiLockCount)
			{
			bSuccess = MakeRoomForAnotherThing();
			if(bSuccess)
				{
				m_ptArray[m_iSlotsUsed] = (T)t;
				m_iSlotsUsed++;
				}
			}
		LeaveCriticalSection(&m_csData);
		LeaveCriticalSection(&m_csModify);
		return bSuccess;
		}
	virtual bool InsertThing(const T t, const int i)
		{
		bool bSuccess = false;
		EnterCriticalSection(&m_csModify);
		EnterCriticalSection(&m_csData);
		if(0 == m_uiLockCount)
			{
			ASSERT((0 <= i) && (i <= m_iSlotsUsed));
			if((0 <= i) && (i <= m_iSlotsUsed))
				{
				bSuccess = MakeRoomForAnotherThing();
				if(bSuccess)
					{
					memmove(&(m_ptArray[i+1]), &(m_ptArray[i]), (m_iSlotsUsed-i)*sizeof(T));
					m_iSlotsUsed++;
					m_ptArray[i] = (T)t;
					}
				}
			}
		LeaveCriticalSection(&m_csData);
		LeaveCriticalSection(&m_csModify);
		return bSuccess;
		}
	virtual bool RemoveThingAtIndex(const int i)
		{
		bool bSuccess = false;
		EnterCriticalSection(&m_csModify);
		EnterCriticalSection(&m_csData);
		if(0 == m_uiLockCount)
			{
			ASSERT((0 <= i) && (i < m_iSlotsUsed));
			if((0 <= i) && (i < m_iSlotsUsed))
				{
				// Preserve ordering
				memmove(&(m_ptArray[i]), &(m_ptArray[i+1]), (m_iSlotsUsed-i-1)*sizeof(T));
				m_iSlotsUsed--;
				bSuccess = true;
				}
			}
		LeaveCriticalSection(&m_csData);
		LeaveCriticalSection(&m_csModify);
		return bSuccess;
		}
	virtual bool RemoveThing(const T t)
		{
		bool bSuccess = false;
		EnterCriticalSection(&m_csModify);
		EnterCriticalSection(&m_csData);
		if(0 == m_uiLockCount)
			{
			const int i = GetThingIndex(t);
			if(-1 != i)
				{
				// Preserve relative ordering of elements
				memmove(&(m_ptArray[i]), &(m_ptArray[i+1]), (m_iSlotsUsed-i-1)*sizeof(T));
				m_iSlotsUsed--;
				bSuccess = true;
				}
			}
		LeaveCriticalSection(&m_csData);
		LeaveCriticalSection(&m_csModify);
		return bSuccess;
		}
	virtual bool RemoveAllThings()
		{
		bool bSuccess = false;
		EnterCriticalSection(&m_csModify);
		EnterCriticalSection(&m_csData);
		if(0 == m_uiLockCount)
			{
			m_iSlotsUsed = 0;
			bSuccess = true;
			}
		LeaveCriticalSection(&m_csData);
		LeaveCriticalSection(&m_csModify);
		return bSuccess;
		}
	virtual bool SwapThingsAtIndices(const int i, const int j)
		{
		bool bSuccess = false;
		EnterCriticalSection(&m_csModify);
		EnterCriticalSection(&m_csData);
		if(0 == m_uiLockCount)
			{
			ASSERT((0 <= i) && (i < m_iSlotsUsed) && (0 <= j) && (j < m_iSlotsUsed));
			if((0 <= i) && (i < m_iSlotsUsed) && (0 <= j) && (j < m_iSlotsUsed))
				{
				T tTemp = m_ptArray[i];
				m_ptArray[i] = m_ptArray[j];
				m_ptArray[j] = tTemp;
				bSuccess = true;
				}
			}
		LeaveCriticalSection(&m_csData);
		LeaveCriticalSection(&m_csModify);
		return bSuccess;
		}
	// Methods that do not modify the collection
	virtual int GetSize()
		{
		EnterCriticalSection(&m_csData);
		const int iReturn = m_iSlotsUsed;
		LeaveCriticalSection(&m_csData);
		return iReturn;
		}
	virtual bool Lock()
		{
		EnterCriticalSection(&m_csData);
		m_uiLockCount++;
		ASSERT(0 < m_uiLockCount);  // Detect overflow
		LeaveCriticalSection(&m_csData);
		return true;  // Always locks
		}
	virtual bool Unlock()
		{
		EnterCriticalSection(&m_csData);
		ASSERT(0 != m_uiLockCount);
		if(0 != m_uiLockCount)
			{
			m_uiLockCount--;
			}
		LeaveCriticalSection(&m_csData);
		return (0 == m_uiLockCount);  // Return value answers "Unlocked?"
		}
	virtual bool BlockModificationByOtherThreads()
		{
		EnterCriticalSection(&m_csModify);
		return true;  // Always grabs the m_csModify CRITICAL_SECTION
		}
	virtual bool AllowModificationByOtherThreads()
		{
		LeaveCriticalSection(&m_csModify);
		return true;  // Always frees the m_csModify CRITICAL_SECTION
		}
	virtual T GetThingAtIndex(const int i)
		{
		T tReturn;
		memset(&tReturn, 0, sizeof(T));
		EnterCriticalSection(&m_csData);
		ASSERT((0 <= i) && (i < m_iSlotsUsed));
		if((0 <= i) && (i < m_iSlotsUsed))
			{
			tReturn = m_ptArray[i];
			}
		LeaveCriticalSection(&m_csData);
		return tReturn;
		}
	virtual bool SetThingAtIndex(const T t, const int i)
		{
		bool bSuccess = false;
		EnterCriticalSection(&m_csData);
		ASSERT((0 <= i) && (i < m_iSlotsUsed));
		if((0 <= i) && (i < m_iSlotsUsed))
			{
			m_ptArray[i] = t;
			bSuccess = true;
			}
		LeaveCriticalSection(&m_csData);
		return bSuccess;
		}
	virtual int GetThingIndex(const T t)
		{
		int iReturn = -1;
		EnterCriticalSection(&m_csData);
		// Count up to preserve relative ordering of elements
		for(int i = 0 ; i < m_iSlotsUsed ; i++)
			{
			if(0 == memcmp(&t, &(m_ptArray[i]), sizeof(T)))
				{
				iReturn = i;
				break;
				}
			}
		LeaveCriticalSection(&m_csData);
		return iReturn;
		}
	typedef bool (*GROWABLE_THING_COLLECTION_FILTER)(const T& rt, void* pvFilterData);
	virtual int GetFilteredThingIndex(GROWABLE_THING_COLLECTION_FILTER gtcfFilter, void* const pvFilterData)
		{
		ASSERT(0 != gtcfFilter);
		int iReturn = -1;
		EnterCriticalSection(&m_csData);
		// Count up to preserve relative ordering of elements
		for(int i = 0 ; (-1 == iReturn) && (i < m_iSlotsUsed) ; i++)
			{
			if(gtcfFilter(m_ptArray[i], pvFilterData))
				{
				iReturn = i;
				}
			}
		LeaveCriticalSection(&m_csData);
		return iReturn;
		}
	// Methods that do not modify the collection and work only when it is locked
	virtual T* GetPointerToThingAtIndex(const int i)
		{
		T* ptReturn = 0;
		EnterCriticalSection(&m_csData);
		ASSERT(0 < m_uiLockCount);
		if(0 < m_uiLockCount)
			{
			ASSERT((0 <= i) && (i < m_iSlotsUsed));
			if((0 <= i) && (i < m_iSlotsUsed))
				{
				ptReturn = &(m_ptArray[i]);
				}
			}
		LeaveCriticalSection(&m_csData);
		return ptReturn;
		}
	virtual T* GetPointerToThing(const T t)
		{
		T* ptReturn = 0;
		EnterCriticalSection(&m_csData);
		ASSERT(0 < m_uiLockCount);
		if(0 < m_uiLockCount)
			{
			for(int i = m_iSlotsUsed-1 ; (0 == ptReturn) && (0 <= i) ; i--)
				{
				if(0 == memcmp(&t, &(m_ptArray[i]), sizeof(T)))
					{
					ptReturn = &(m_ptArray[i]);
					}
				}
			}
		LeaveCriticalSection(&m_csData);
		return ptReturn;
		}

	protected:
	// Method to grow the storage when necessary
	virtual bool MakeRoomForAnotherThing()
		{
		bool bSuccess = true;
		ASSERT(0 == m_uiLockCount);
		if(m_iSlotsUsed == m_iSlotsAllocated)
			{
			T* const Oldm_ptArray = m_ptArray;
			const int iSlotsDesired = m_iSlotsAllocated+m_iGrowSize;
			if(0 == m_ptArray)
				{
				m_ptArray = (T*)LocalAlloc(LMEM_FIXED, iSlotsDesired*sizeof(T));
				}
			else
				{
				m_ptArray = (T*)LocalReAlloc(m_ptArray, iSlotsDesired*sizeof(T), LMEM_MOVEABLE);
				}
			if(0 == m_ptArray)
				{
				// Unable to allocate memory - keep old memory
				m_ptArray = Oldm_ptArray;
				bSuccess = false;
				}
			else
				{
				m_iSlotsAllocated = iSlotsDesired;
				}
			}
		return bSuccess;
		}
	void CopyAnotherGrowableThingCollection(const GrowableThingCollection& rgtc)
		{
		m_ptArray = (T*)LocalAlloc(LMEM_FIXED, rgtc.m_iSlotsAllocated*sizeof(T));
		if(0 != m_ptArray)
			{
			m_iSlotsUsed = rgtc.m_iSlotsUsed;
			m_iSlotsAllocated = rgtc.m_iSlotsAllocated;
			memcpy(m_ptArray, rgtc.m_ptArray, m_iSlotsUsed*sizeof(T));
			}
		else
			{
			m_iSlotsUsed = 0;
			m_iSlotsAllocated = 0;
			}
		m_iGrowSize = rgtc.m_iGrowSize;
		m_uiLockCount = 0;
		}

	CRITICAL_SECTION m_csData;
	CRITICAL_SECTION m_csModify;
	T* m_ptArray;
	int m_iSlotsUsed;
	int m_iSlotsAllocated;
	int m_iGrowSize;
	unsigned int m_uiLockCount;
	};

#endif  // !defined(TOOL_BOX_HEADER)
