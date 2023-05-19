CXX = g++
CXXFLAGS = -Wall -Wextra -pedantic -std=c++11
LIBS = -lpcap

TARGET = out/snoopy_printer out/device_list

all: $(TARGET)

out/snoopy_printer: src/snoopy_printer.cc src/util.h
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

out/device_list: src/device_list.cc
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(TARGET)
