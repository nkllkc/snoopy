CXX = g++
CXXFLAGS = -Wall -Wextra -pedantic -std=c++11
LIBS = -lpcap

TARGET = out/snoopy_printer
SRCS = src/snoopy_printer.cc

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(TARGET)
