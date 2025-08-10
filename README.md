
# injector-lib (InjectorLib.dll)

injector-lib defines and exposes functions relating to working with DLL's. Used by the [Brick Rigs Injector](https://github.com/tubaplayerdis/BR-Injector)

# Exposed Functions

---

## `InjectDLL`

Injects a dll given a path and process name

### Definition

```c
int InjectDll(const wchar_t* dll_path_name, const wchar_t* process_name)
```

### Parameters

- `dll_path_name`: The full path and file name of the dll
  **Example**: "C:/Users/CoolDude/CoolMod.dll"
- `process_name`: Name of the process to inject into.

### Returns

* 0 - Success
* 1 - Process Not Found
* 2 - Dll Not Found
* 3 - Process Opening Failure
* 4 - DLL already loaded
* 5 - Injection Failure

---

## `DLLIsLoaded`

Checks to see if a dll is already loaded

### Defenition

```c
int DLLIsLoaded(const wchar_t* dll_name, const wchar_t* process_name)
```

### Parameters

- `dll_name`: The file name of the dll
  **Example**: "CoolMod.dll"
- `process_name`: Name of the process to inject into.

### Returns

* 0 - Not Loaded  
* 1 - Loaded  
* 2 - Process Not Found  
* 3 - Process Cant Open

---

## `EjectDLL`

Ejects a dll form a process.

### Declaration

```c
int EjectDLL(const wchar_t* dll_name const wchar_t* process_name)
```

### Parameters

- `dll_name`: The file name of the dll
  **Example**: "CoolMod.dll"
- `process_name`: Name of the process to inject into.

### Returns

* 0 - Ejected DLL  
* 1 - Failed to Eject DLL  
* 2 - Process Not Found

---