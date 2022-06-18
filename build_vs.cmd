@ECHO OFF
@SETLOCAL

rd /s/q build_vs
mkdir build_vs
@REM pushd
cd build_vs
cmake ..
cmake --build .
@REM popd
cd ..
xcopy GB28181.ini build_vs\Debug\
cd build_vs\Debug
gbexecer
