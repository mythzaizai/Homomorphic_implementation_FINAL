CXX = g++
CXXFLAGS = -O3 -funroll-loops -march=native -std=c++11 -pthread -I. -I./include -I../fftw-3.3.5-dll64
DEPS = -lntl -lgmp -lfftw3 -lm

all: clean math_operations

clean:
	$(RM) math_operations math_operations.o lwehe.o ntruhe.o fft.o sampler.o keygen.o libfinal.a

math_operations: FINAL.h libfinal.a
	$(CXX) $(CXXFLAGS) -o math_operations math_operations.cpp libfinal.a $(DEPS)

libfinal.a: include/params.h ntruhe.o lwehe.o keygen.o fft.o sampler.o
	$(AR) -q libfinal.a ntruhe.o lwehe.o keygen.o fft.o sampler.o

ntruhe.o: include/ntruhe.h keygen.o sampler.o lwehe.o src/ntruhe.cpp
	$(CXX) $(CXXFLAGS) -c src/ntruhe.cpp

lwehe.o: include/lwehe.h keygen.o sampler.o src/lwehe.cpp
	$(CXX) $(CXXFLAGS) -c src/lwehe.cpp

keygen.o: include/keygen.h sampler.o fft.o src/keygen.cpp
	$(CXX) $(CXXFLAGS) -c src/keygen.cpp

fft.o: include/fft.h
	$(CXX) $(CXXFLAGS) -c src/fft.cpp

sampler.o: include/sampler.h include/params.h src/sampler.cpp
	$(CXX) $(CXXFLAGS) -c src/sampler.cpp
