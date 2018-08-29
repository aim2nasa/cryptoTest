CXX = g++
CXXFLAGS = -std=c++11

TARGET = facTest
SRCS = facTest.cpp
OBJS = ${SRCS:.cpp=.o}

CATCH2_INCLUDE_DIRS=/usr/include

INCLUDES = $(CATCH2_INCLUDE_DIRS)

all : $(TARGET)
	@echo $@:$(TARGET)...

$(TARGET) : $(OBJS)
	@echo $@:$^...
	$(CXX) -o $@ $^

%.o : %.cpp
	@echo $@:$<...
	$(CXX) -c $< $(CXXFLAGS)

clean:
	@echo $@...
	rm -rf *.o $(TARGET)
