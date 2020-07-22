## vs-autocompiler

Compiles a project with multiplie Visual Studio backends.
Supports: VS2019, VS2017, VS2015, VS2013, VS2012, VS2010.

Run autocompiler.ps1 from directory with the project and the .sln file.
Set $out parameter for where to generate the compiled files, e.g.:

```
git clone https://github.com/stephenfewer/ReflectiveDLLInjection
cd ReflectiveDLLInjection
C:\Users\me\autocompiler.ps1 -out C:\Users\me\output
```

