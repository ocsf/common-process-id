Compile:
```
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON ..
make
ctest
```

Set `-DBUILD_TESTING=OFF` to disable testing.

CLI Use:
```
./cpid_cli <PID>
```
